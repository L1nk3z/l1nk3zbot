package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// ===== Сохранение пользователей =====
func saveUsersToFile(allUsers map[int64]string) {
	f, err := os.OpenFile("users.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Println("Ошибка открытия файла users.json:", err)
		return
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(allUsers); err != nil {
		log.Println("Ошибка кодирования users.json:", err)
	}
}

// ===== Загрузка пользователей (whitelist: ID -> username) =====
func loadUsersFromFile() map[int64]string {
	allUsers := make(map[int64]string)
	f, err := os.Open("users.json")
	if err != nil {
		return allUsers
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	// Поддержка строковых ключей в JSON (например "1087968824")
	var raw map[string]string
	if err := decoder.Decode(&raw); err != nil {
		log.Println("Ошибка декодирования users.json:", err)
		return allUsers
	}
	for k, v := range raw {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			continue
		}
		allUsers[id] = v
	}
	return allUsers
}

// ===== Проверка доступа: admin или ID в whitelist =====
func isAllowed(userID int64, whitelist map[int64]string, adminID int64) bool {
	if userID == adminID {
		return true
	}
	_, ok := whitelist[userID]
	return ok
}

// Текст кнопки запроса доступа (только для неавторизованных)
const requestAccessButtonText = "📩 Запросить доступ у администратора"

const webUsersFile = "web_users.json"
const webAuthPort = "8080"

// WebAppURL — ссылка на Web App. Для авторизации по логину/паролю укажите URL сервера, где запущен бот (и папка web/ отдаётся по HTTP), например https://your-domain.com/
var webAppURL = "https://l1nk3z.github.io/l1nk3zbot/"

var (
	webUsers   = make(map[string]string) // login -> password
	webLinks   = make(map[string]string) // telegram username -> login
	webUsersMu sync.RWMutex
)

func loadWebUsers() {
	webUsersMu.Lock()
	defer webUsersMu.Unlock()
	data, err := os.ReadFile(webUsersFile)
	if err != nil {
		return
	}
	var out struct {
		Users map[string]string `json:"users"`
		Links map[string]string `json:"links"`
	}
	if json.Unmarshal(data, &out) == nil && out.Users != nil {
		webUsers = out.Users
	}
	if out.Links != nil {
		webLinks = out.Links
	}
}

func saveWebUsers() {
	webUsersMu.Lock()
	cp := make(map[string]string)
	lp := make(map[string]string)
	for k, v := range webUsers {
		cp[k] = v
	}
	for k, v := range webLinks {
		lp[k] = v
	}
	webUsersMu.Unlock()
	data, _ := json.MarshalIndent(struct {
		Users map[string]string `json:"users"`
		Links map[string]string `json:"links,omitempty"`
	}{cp, lp}, "", "  ")
	_ = os.WriteFile(webUsersFile, data, 0644)
}

func generatePassword(n int) string {
	const letters = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// sendAndTrack отправляет сообщение и сохраняет ID в track[chatID] для последующего удаления при /revoke.
func sendAndTrack(bot *tgbotapi.BotAPI, msg tgbotapi.Chattable, track map[int64][]int) (tgbotapi.Message, error) {
	sent, err := bot.Send(msg)
	if err != nil {
		return tgbotapi.Message{}, err
	}
	if sent.MessageID != 0 {
		track[sent.Chat.ID] = append(track[sent.Chat.ID], sent.MessageID)
	}
	return sent, nil
}

func handleWebAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var buf bytes.Buffer
	buf.ReadFrom(r.Body)
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if json.NewDecoder(&buf).Decode(&req) != nil || req.Login == "" || req.Password == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]bool{"ok": false})
		return
	}
	webUsersMu.RLock()
	ok := webUsers[req.Login] == req.Password
	webUsersMu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]bool{"ok": false})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func main() {
	bot, err := tgbotapi.NewBotAPI("")
	if err != nil {
		log.Panic(err)
	}

	bot.Debug = false
	log.Printf("✅ Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	const adminID int64 = 1613348804
	allUsers := loadUsersFromFile()
	loadWebUsers()
	waitingForAdminMessage := make(map[int64]bool)
	pendingAccessRequests := make(map[int64]bool)
	botMessageIDsByChat := make(map[int64][]int)

	// Отложенное сохранение users.json (раз в 3 с после изменений) — меньше нагрузка на диск
	saveChan := make(chan struct{}, 1)
	go func() {
		for range saveChan {
			time.Sleep(3 * time.Second)
			saveUsersToFile(allUsers)
		}
	}()

	// HTTP API для авторизации Web App (логин/пароль от админа)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth", handleWebAuth)
	if _, err := os.Stat("web"); err == nil {
		if _, errZerno := os.Stat("zerno"); errZerno == nil {
			mux.Handle("/zerno/", http.StripPrefix("/zerno/", http.FileServer(http.Dir("zerno"))))
		}
		if _, errHelp := os.Stat("helpzerno"); errHelp == nil {
			mux.Handle("/helpzerno/", http.StripPrefix("/helpzerno/", http.FileServer(http.Dir("helpzerno"))))
		}
		if _, errQR := os.Stat("qr.jpg"); errQR == nil {
			mux.HandleFunc("/qr.jpg", func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, "qr.jpg")
			})
		}
		mux.HandleFunc("/web_users.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			http.ServeFile(w, r, webUsersFile)
		})
		mux.Handle("/", http.FileServer(http.Dir("web")))
		go func() {
			if e := http.ListenAndServe(":"+webAuthPort, mux); e != nil {
				log.Println("Web auth server:", e)
			}
		}()
		log.Printf("Web auth: http://localhost:%s (папка web/)", webAuthPort)
	}

	for update := range updates {
		// === 🔹 Обработка Web App данных ===
		if update.Message != nil && update.Message.WebAppData != nil {
			webAppData := update.Message.WebAppData
			user := update.Message.From
			// Доступ к Web App только по whitelist (admin или ID в users.json)
			if user == nil || !isAllowed(user.ID, allUsers, adminID) {
				if user != nil {
					reqKb := tgbotapi.NewReplyKeyboard(tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton(requestAccessButtonText)))
					msgNoAccess := tgbotapi.NewMessage(update.Message.Chat.ID, "У вас нет доступа к боту. Ваш ID: "+strconv.FormatInt(user.ID, 10)+". Нажмите кнопку ниже, чтобы отправить запрос администратору.")
					msgNoAccess.ReplyMarkup = reqKb
					sendAndTrack(bot, msgNoAccess, botMessageIDsByChat)
				}
				continue
			}

			log.Printf("[WEBAPP] Получены данные от %s (ID: %d): %s", user.UserName, user.ID, webAppData.Data)

			// Просто подтверждаем получение данных
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "✅ Данные получены в Web App")
			sendAndTrack(bot, msg, botMessageIDsByChat)

			// Обрабатываем данные из Web App
			switch webAppData.Data {
			case "📞 Номера":
				log.Printf("[WEBAPP] Обработка меню номеров")
				// Создаем inline-клавиатуру для выбора типа номеров
				inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
					tgbotapi.NewInlineKeyboardRow(
						tgbotapi.NewInlineKeyboardButtonData("📞 Бариста", "webapp_barista"),
						tgbotapi.NewInlineKeyboardButtonData("🛡️ Спец Службы", "webapp_services"),
					),
					tgbotapi.NewInlineKeyboardRow(
						tgbotapi.NewInlineKeyboardButtonData("☕ Кофейни Surf", "webapp_coffeeshops"),
					),
				)

				msgOut := tgbotapi.NewMessage(update.Message.Chat.ID, "📞 *Выбери категорию номеров:*")
				msgOut.ParseMode = "Markdown"
				msgOut.ReplyMarkup = inlineKeyboard
				sendAndTrack(bot, msgOut, botMessageIDsByChat)

			case "💼 Помощник":
				log.Printf("[WEBAPP] Обработка меню помощника")
				// Показываем меню помощника
				blendKeyboard := tgbotapi.NewReplyKeyboard(
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("📦 Кбжу"),
						tgbotapi.NewKeyboardButton("📦 Состав десертов"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("📦 График работы"),
						tgbotapi.NewKeyboardButton("📦 Рекламация"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
					),
				)
				msgOut := tgbotapi.NewMessage(update.Message.Chat.ID, "☕ Выбери интересующий тебя раздел:")
				msgOut.ReplyMarkup = blendKeyboard
				sendAndTrack(bot, msgOut, botMessageIDsByChat)

			case "📦 Все о зерне":
				log.Printf("[WEBAPP] Обработка меню зерна")
				// Показываем меню зерна
				blendKeyboard := tgbotapi.NewReplyKeyboard(
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("📦 Зерно"),
						tgbotapi.NewKeyboardButton("📦 Настройка"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
					),
				)
				msgOut := tgbotapi.NewMessage(update.Message.Chat.ID, "☕ Выбери интересующий тебя раздел:")
				msgOut.ReplyMarkup = blendKeyboard
				sendAndTrack(bot, msgOut, botMessageIDsByChat)

			case "📷 Бот Сёрфа":
				log.Printf("[WEBAPP] Обработка QR кода")
				// Отправляем QR код
				file, err := os.Open("qr.jpg")
				if err != nil {
					log.Printf("[WEBAPP] Ошибка открытия QR: %v", err)
					sendAndTrack(bot, tgbotapi.NewMessage(update.Message.Chat.ID, "⚠️ Не удалось найти изображение QR."), botMessageIDsByChat)
				} else {
					defer file.Close()
					photo := tgbotapi.NewPhoto(update.Message.Chat.ID, tgbotapi.FileReader{Name: "qr.jpg", Reader: file})
					photo.Caption = "Вот твой QR-код 📷"
					sendAndTrack(bot, photo, botMessageIDsByChat)
				}
			default:
				log.Printf("[WEBAPP] Неизвестная команда: %s", webAppData.Data)
				sendAndTrack(bot, tgbotapi.NewMessage(update.Message.Chat.ID, "❌ Неизвестная команда: "+webAppData.Data), botMessageIDsByChat)
			}
			continue
		}

		// === 🔹 Обработка Inline-кнопок (CallbackQuery) ===
		if update.CallbackQuery != nil {
			callback := update.CallbackQuery
			if !isAllowed(callback.From.ID, allUsers, adminID) {
				bot.Request(tgbotapi.NewCallback(callback.ID, "Нет доступа к боту."))
				continue
			}
			data := callback.Data

			// Обработка webapp callback'ов
			if strings.HasPrefix(data, "webapp_") {
				switch data {
				case "webapp_barista":
					// Показываем inline-клавиатуру с бариста
					inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("Евгений", "phone_Evgeiny"),
							tgbotapi.NewInlineKeyboardButtonData("Алина Менеджер", "phone_Alina(meng)"),
							tgbotapi.NewInlineKeyboardButtonData("Алина Младшая", "phone_Alina(mlad)"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("Анджелика", "phone_Angelika"),
							tgbotapi.NewInlineKeyboardButtonData("Азалия", "phone_Azalia"),
							tgbotapi.NewInlineKeyboardButtonData("Марсель", "phone_Marsel"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("Настя", "phone_Nastya"),
							tgbotapi.NewInlineKeyboardButtonData("Айнур", "phone_Ainyr"),
							tgbotapi.NewInlineKeyboardButtonData("Леонид", "phone_Leonid"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("Альбина", "phone_Albina"),
							tgbotapi.NewInlineKeyboardButtonData("Алина Старшая", "phone_Alina(zel)"),
						),
					)

					msgOut := tgbotapi.NewMessage(callback.Message.Chat.ID, "☕ Выбери бариста, чтобы увидеть номер:")
					msgOut.ReplyMarkup = inlineKeyboard
					sendAndTrack(bot, msgOut, botMessageIDsByChat)

				case "webapp_services":
					// Показываем inline-клавиатуру со службами
					inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("Охрана(Виктор)", "phone_Oxrana"),
							tgbotapi.NewInlineKeyboardButtonData("Кондиционер(Ильфир)", "phone_Xolodilnik"),
							tgbotapi.NewInlineKeyboardButtonData("Сантехник(Виктор)", "phone_Santexkin"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("Электрик(Алмаз)", "phone_Electric"),
							tgbotapi.NewInlineKeyboardButtonData("Мастер(Рафис)", "phone_Master"),
						),
					)

					msgOut := tgbotapi.NewMessage(callback.Message.Chat.ID, "🛡️ Выбери службу, чтобы увидеть номер:")
					msgOut.ReplyMarkup = inlineKeyboard
					sendAndTrack(bot, msgOut, botMessageIDsByChat)

				case "webapp_coffeeshops":
					// Показываем inline-клавиатуру с кофейнями
					inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("xSaveIn", "phone_xSaveIn"),
							tgbotapi.NewInlineKeyboardButtonData("xMuses", "phone_xMuses"),
							tgbotapi.NewInlineKeyboardButtonData("xLovers", "phone_xLovers"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("xKremlin", "phone_xKremlin"),
							tgbotapi.NewInlineKeyboardButtonData("xJoe", "phone_xJoe"),
							tgbotapi.NewInlineKeyboardButtonData("xItPark", "phone_xItPark"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("xIva", "phone_xIva"),
							tgbotapi.NewInlineKeyboardButtonData("xCult", "phone_xCult"),
							tgbotapi.NewInlineKeyboardButtonData("xLetskoy", "phone_xLetskoy"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("xUnofficial", "phone_xUnofficial"),
							tgbotapi.NewInlineKeyboardButtonData("xInside", "phone_xInside"),
							tgbotapi.NewInlineKeyboardButtonData("xKasatka", "phone_xKasatka"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("xMega", "phone_xMega"),
							tgbotapi.NewInlineKeyboardButtonData("xSuite", "phone_xSuite"),
							tgbotapi.NewInlineKeyboardButtonData("xKazanMall", "phone_xKazanMall"),
						),
						tgbotapi.NewInlineKeyboardRow(
							tgbotapi.NewInlineKeyboardButtonData("xArch", "phone_xArch"),
							tgbotapi.NewInlineKeyboardButtonData("xNokka", "phone_xNokka"),
						),
					)

					msgOut := tgbotapi.NewMessage(callback.Message.Chat.ID, "☕ Выбери кофейню, чтобы увидеть номер:")
					msgOut.ReplyMarkup = inlineKeyboard
					sendAndTrack(bot, msgOut, botMessageIDsByChat)
				}

				bot.Request(tgbotapi.NewCallback(callback.ID, ""))
				continue
			}

			phoneNumbers := map[string]string{
				"phone_xSaveIn":     "+",
				"phone_xMuses":      "+",
				"phone_xLovers":     "+",
				"phone_xKremlin":    "+",
				"phone_xJoe":        "+",
				"phone_xItPark":     "+",
				"phone_xIva":        "+",
				"phone_xCult":       "+",
				"phone_xLetskoy":    "+",
				"phone_xUnofficial": "+",
				"phone_xInside":     "+",
				"phone_xKasatka":    "+",
				"phone_xMega":       "+",
				"phone_xSuite":      "+",
				"phone_xKazanMall":  "+",
				"phone_xArch":       "+",
				"phone_xNokka":      "+",
			}
			phoneBarista := map[string]string{
				"phone_Evgeiny":     "+",
				"phone_Alina(meng)": "+",
				"phone_Alina(mlad)": "+",
				"phone_Angelika":    "++",
				"phone_Azalia":      "++",
				"phone_Marsel":      "++",
				"phone_Nastya":      "++",
				"phone_Ainyr":       "++",
				"phone_Leonid":      "++",
				"phone_Albina":      "++",
				"phone_Alina(zel)":  "++",
				"phone_Sereja":      "++",
			}

			phoneSlyzb := map[string]string{
				"phone_Oxrana":     "++",
				"phone_Xolodilnik": "++",
				"phone_Santexkin":  "++",
				"phone_Electric":   "++",
				"phone_Master":     "+",
				"phone_ledgen":     "++",
			}
			Baristahelp := map[string]string{
				"help_kbzy":   "https://docs.google.com/spreadsheets/d/1WO1vzivTrDq2E7qVbyXkZWUaQty_3424uGM8uVspLWI/edit?usp=drivesdk",
				"help_sostav": "https://docs.google.com/spreadsheets/d/1osNe5k1iwYFbcvX_aU3B01YOwaCub28ThB73003OuBg/edit?usp=drivesdk",
				"help_grafik": "https://docs.google.com/spreadsheets/d/1PyP-_4pgiz7Ok6eqfk2YU6yrhpkO2snUN1wZ7FqMMNI/edit?usp=drivesdk",
			}

			// Обработка номеров служб
			if number, ok := phoneSlyzb[data]; ok {
				var name string
				switch data {
				case "phone_Oxrana":
					name = "Охрана (Виктор)"
				case "phone_Xolodilnik":
					name = "Кондиционер (Ильфир)"
				case "phone_Santexkin":
					name = "Сантехник (Виктор)"
				case "phone_Electric":
					name = "Электрик (Алмаз)"
				case "phone_Master":
					name = "Мастер (Рафис)"
				case "phone_ledgen":
					name = "Ледген (Ильдар)"
				default:
					name = "Служба"
				}

				message := fmt.Sprintf("🛡️ *%s*\n📱 Номер: `%s`", name, number)
				msg := tgbotapi.NewMessage(callback.Message.Chat.ID, message)
				msg.ParseMode = "Markdown"
				sendAndTrack(bot, msg, botMessageIDsByChat)
			}

			// Обработка ссылок помощника
			if number, ok := Baristahelp[data]; ok {
				msg := tgbotapi.NewMessage(callback.Message.Chat.ID, fmt.Sprintf("🔗 %s", number))
				sendAndTrack(bot, msg, botMessageIDsByChat)
			}

			// Обработка номеров бариста
			if number, ok := phoneBarista[data]; ok {
				// Форматируем сообщение с номером бариста
				var name string
				switch data {
				case "phone_Evgeiny":
					name = "Евгений"
				case "phone_Alina(meng)":
					name = "Алина Менеджер"
				case "phone_Alina(mlad)":
					name = "Алина Младшая"
				case "phone_Angelika":
					name = "Анжелика"
				case "phone_Azalia":
					name = "Азалия"
				case "phone_Marsel":
					name = "Марсель"
				case "phone_Nastya":
					name = "Настя"
				case "phone_Ainyr":
					name = "Айнур"
				case "phone_Leonid":
					name = "Леонид"
				case "phone_Albina":
					name = "Альбина"
				case "phone_Alina(zel)":
					name = "Алина Старшая"
				case "phone_Sereja":
					name = "Серёжа"
				default:
					name = "Бариста"
				}

				message := fmt.Sprintf("📞 *%s*\n📱 Номер: `%s`", name, number)
				msg := tgbotapi.NewMessage(callback.Message.Chat.ID, message)
				msg.ParseMode = "Markdown"
				sendAndTrack(bot, msg, botMessageIDsByChat)
			}

			// Обработка номеров кофеен
			if number, ok := phoneNumbers[data]; ok {
				var coffeeShop string
				switch data {
				case "phone_xSaveIn":
					coffeeShop = "xSaveIn"
				case "phone_xMuses":
					coffeeShop = "xMuses"
				case "phone_xLovers":
					coffeeShop = "xLovers"
				case "phone_xKremlin":
					coffeeShop = "xKremlin"
				case "phone_xJoe":
					coffeeShop = "xJoe"
				case "phone_xItPark":
					coffeeShop = "xItPark"
				case "phone_xIva":
					coffeeShop = "xIva"
				case "phone_xCult":
					coffeeShop = "xCult"
				case "phone_xLetskoy":
					coffeeShop = "xLetskoy"
				case "phone_xUnofficial":
					coffeeShop = "xUnofficial"
				case "phone_xInside":
					coffeeShop = "xInside"
				case "phone_xKasatka":
					coffeeShop = "xKasatka"
				case "phone_xMega":
					coffeeShop = "xMega"
				case "phone_xSuite":
					coffeeShop = "xSuite"
				case "phone_xKazanMall":
					coffeeShop = "xKazanMall"
				case "phone_xArch":
					coffeeShop = "xArch"
				case "phone_xNokka":
					coffeeShop = "xNokka"
				default:
					coffeeShop = "Кофейня"
				}

				message := fmt.Sprintf("☕ *%s*\n📱 Номер: `%s`", coffeeShop, number)
				msg := tgbotapi.NewMessage(callback.Message.Chat.ID, message)
				msg.ParseMode = "Markdown"
				sendAndTrack(bot, msg, botMessageIDsByChat)
			}

			// ✅ Закрываем "часики" у кнопки
			bot.Request(tgbotapi.NewCallback(callback.ID, ""))
			continue
		}

		// === 🔹 Дальше идёт твоя стандартная обработка сообщений ===
		if update.Message == nil {
			continue
		}

		msg := update.Message
		user := msg.From
		text := msg.Text

		if user == nil || text == "" {
			continue
		}

		log.Printf("[CHAT:%d] %s (ID: %d): %s", msg.Chat.ID, user.UserName, user.ID, text)

		// === Неавторизованные: запрос доступа или пересылка сообщений админу ===
		if !isAllowed(user.ID, allUsers, adminID) {
			if text == requestAccessButtonText {
				accPart := "@" + user.UserName
				if user.UserName == "" {
					accPart = "(без @username)"
				}
				adminReq := fmt.Sprintf("{Пользователь} - Прошу предоставить мне доступ - %d - %s.", user.ID, accPart)
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, adminReq), botMessageIDsByChat)
				pendingAccessRequests[user.ID] = true
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "Запрос отправлен. Теперь вы можете писать сообщения — они будут пересылаться администратору."), botMessageIDsByChat)
			} else if pendingAccessRequests[user.ID] {
				adminFwd := fmt.Sprintf("[Сообщение от ID %d @%s]: %s", user.ID, user.UserName, text)
				if user.UserName == "" {
					adminFwd = fmt.Sprintf("[Сообщение от ID %d]: %s", user.ID, text)
				}
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, adminFwd), botMessageIDsByChat)
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "Сообщение доставлено администратору."), botMessageIDsByChat)
			} else {
				reqKb := tgbotapi.NewReplyKeyboard(tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton(requestAccessButtonText)))
				msgNoAccess := tgbotapi.NewMessage(msg.Chat.ID, "У вас нет доступа к боту. Ваш ID: "+strconv.FormatInt(user.ID, 10)+". Нажмите кнопку ниже, чтобы отправить запрос администратору.")
				msgNoAccess.ReplyMarkup = reqKb
				sendAndTrack(bot, msgNoAccess, botMessageIDsByChat)
			}
			continue
		}

		// === Обновляем username в whitelist для разрешённого пользователя ===
		if user.ID != adminID {
			username := user.UserName
			if username == "" {
				username = user.FirstName
			}
			allUsers[user.ID] = username
			select {
			case saveChan <- struct{}{}:
			default:
			}
		}
		if waitingForAdminMessage[user.ID] {
			adminMsg := fmt.Sprintf("⚠️ [FEEDBACK] ⚠️\nОт: %s\nID: %d\nСообщение: %s", user.UserName, user.ID, text)
			_, err := sendAndTrack(bot, tgbotapi.NewMessage(adminID, adminMsg), botMessageIDsByChat)
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ Ошибка при отправке сообщения"), botMessageIDsByChat)
			} else {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "✅ Ваше сообщение отправлено, ожидайте ответа"), botMessageIDsByChat)
			}
			// Снимаем флаг ожидания
			waitingForAdminMessage[user.ID] = false
			continue // не обрабатываем это сообщение дальше
		}

		// === Проверка команд ===
		if msg.IsCommand() {
			command := msg.Command()
			args := msg.CommandArguments()

			switch command {
			case "start":
				if strings.TrimSpace(args) == "webdata" {
					msgOut := tgbotapi.NewMessage(msg.Chat.ID, "Нажмите кнопку ниже, чтобы получить данные для входа на сайт.")
					msgOut.ReplyMarkup = tgbotapi.NewReplyKeyboard(
						tgbotapi.NewKeyboardButtonRow(
							tgbotapi.NewKeyboardButton("🔐 Данные для сайта"),
						),
						tgbotapi.NewKeyboardButtonRow(
							tgbotapi.NewKeyboardButton("🔄 Главное меню"),
						),
					)
					sendAndTrack(bot, msgOut, botMessageIDsByChat)
					break
				}
				mainMenu := tgbotapi.NewReplyKeyboard(
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("ℹ️ Помощь"),
						tgbotapi.NewKeyboardButton("📞 Номера"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("💼 Помощник"),
						tgbotapi.NewKeyboardButton("📦 Все о зерне"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("📷 Бот Сёрфа"),
						tgbotapi.NewKeyboardButton("✉️ Администратору"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("🔐 Данные для сайта"),
					),
					tgbotapi.NewKeyboardButtonRow(
						tgbotapi.NewKeyboardButton("🔄 Главное меню"),
						tgbotapi.NewKeyboardButton("📋 О боте"),
					),
				)
				msgOut := tgbotapi.NewMessage(msg.Chat.ID,
					fmt.Sprintf("👋 Привет, %s!\n\nВыбери нужное действие в меню ниже:", user.FirstName))
				msgOut.ReplyMarkup = mainMenu
				sendAndTrack(bot, msgOut, botMessageIDsByChat)
			case "help":
				// Inline-кнопка для Web App
				webAppBtn := tgbotapi.NewInlineKeyboardButtonWebApp("🚀 Открыть мини-приложение", tgbotapi.WebAppInfo{URL: webAppURL})

				inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
					tgbotapi.NewInlineKeyboardRow(webAppBtn),
				)

				helpText := "🚀 *Мини-приложение Surf Coffee*\n\nНажмите кнопку ниже чтобы открыть приложение с доступом ко всем функциям:"

				msgOut := tgbotapi.NewMessage(msg.Chat.ID, helpText)
				msgOut.ParseMode = "Markdown"
				msgOut.ReplyMarkup = inlineKeyboard
				sendAndTrack(bot, msgOut, botMessageIDsByChat)
			case "admin":
				if len(args) > 0 {
					feedbackText := args
					adminMsg := fmt.Sprintf("⚠️ [FEEDBACK] ⚠️\nОт: %s\nID: %d\nСообщение: %s",
						user.UserName, user.ID, feedbackText)
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, adminMsg), botMessageIDsByChat)
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "✅ Сообщение отправлено администратору!"), botMessageIDsByChat)
				} else {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ Напиши сообщение после /admin [текст]"), botMessageIDsByChat)
				}

			case "send":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ У вас нет прав для этой команды."), botMessageIDsByChat)
					break
				}
				parts := strings.SplitN(args, " ", 2)
				if len(parts) != 2 {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "❌ Формат: /send ID текст_сообщения"), botMessageIDsByChat)
					break
				}
				targetID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "❌ Неверный ID"), botMessageIDsByChat)
					break
				}
				message := parts[1]
				_, err = sendAndTrack(bot, tgbotapi.NewMessage(targetID, "📩 Сообщение от администратора:\n"+message), botMessageIDsByChat)
				if err != nil {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "❌ Ошибка при отправке сообщения"), botMessageIDsByChat)
				} else {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "✅ Сообщение успешно отправлено"), botMessageIDsByChat)
				}

			case "listusers":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ У вас нет прав для этой команды."), botMessageIDsByChat)
					break
				}
				if len(allUsers) == 0 {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Список пользователей пуст."), botMessageIDsByChat)
					break
				}
				var builder strings.Builder
				builder.WriteString("📋 Список пользователей:\n")
				for id, username := range allUsers {
					builder.WriteString(fmt.Sprintf("ID: %d | %s\n", id, username))
				}
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, builder.String()), botMessageIDsByChat)

			case "grant":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ У вас нет прав для этой команды."), botMessageIDsByChat)
					break
				}
				var targetID int64
				var username string
				if msg.ReplyToMessage != nil && msg.ReplyToMessage.From != nil {
					targetID = msg.ReplyToMessage.From.ID
					username = msg.ReplyToMessage.From.UserName
					if username == "" {
						username = msg.ReplyToMessage.From.FirstName
					}
				} else {
					argsTrim := strings.TrimSpace(args)
					if argsTrim == "" {
						sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Использование: /grant <userID> или ответьте /grant на сообщение пользователя."), botMessageIDsByChat)
						break
					}
					var errParse error
					targetID, errParse = strconv.ParseInt(argsTrim, 10, 64)
					if errParse != nil || targetID == 0 {
						sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Использование: /grant <userID> или ответьте /grant на сообщение пользователя."), botMessageIDsByChat)
						break
					}
					username = "unknown"
				}
				if username == "" {
					username = "unknown"
				}
				allUsers[targetID] = username
				select {
				case saveChan <- struct{}{}:
				default:
				}
				delete(pendingAccessRequests, targetID)
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, "✅ Доступ выдан пользователю ID: "+strconv.FormatInt(targetID, 10)), botMessageIDsByChat)
				sendAndTrack(bot, tgbotapi.NewMessage(targetID, "Вам выдан доступ к боту. Можете отправить /start."), botMessageIDsByChat)

			case "revoke":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ У вас нет прав для этой команды."), botMessageIDsByChat)
					break
				}
				argsTrim := strings.TrimSpace(args)
				if argsTrim == "" {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Использование: /revoke <userID>"), botMessageIDsByChat)
					break
				}
				revokeID, errRevoke := strconv.ParseInt(argsTrim, 10, 64)
				if errRevoke != nil {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "❌ Неверный ID."), botMessageIDsByChat)
					break
				}
				delete(allUsers, revokeID)
				delete(pendingAccessRequests, revokeID)
				select {
				case saveChan <- struct{}{}:
				default:
				}
				// Удаляем все сообщения бота в чате пользователя и убираем клавиатуру
				for _, msgID := range botMessageIDsByChat[revokeID] {
					_, _ = bot.Send(tgbotapi.NewDeleteMessage(revokeID, msgID))
				}
				delete(botMessageIDsByChat, revokeID)
				revokeMsg := tgbotapi.NewMessage(revokeID, "Доступ к боту отозван.")
				revokeMsg.ReplyMarkup = tgbotapi.NewRemoveKeyboard(true)
				sendAndTrack(bot, revokeMsg, botMessageIDsByChat)
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, "✅ Доступ для ID "+strconv.FormatInt(revokeID, 10)+" отозван."), botMessageIDsByChat)

			case "webadd":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ Нет прав."), botMessageIDsByChat)
					break
				}
				parts := strings.Fields(args)
				login := ""
				if len(parts) > 0 {
					login = strings.TrimSpace(parts[0])
				}
				targetUsername := ""
				if len(parts) > 1 {
					targetUsername = strings.TrimPrefix(strings.TrimSpace(parts[1]), "@")
				}
				if login == "" {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Использование: /webadd <логин> [@username] — создаёт учётную запись для Web App. Если указан @username, данные отправятся пользователю."), botMessageIDsByChat)
					break
				}
				webUsersMu.Lock()
				if _, exists := webUsers[login]; exists {
					webUsersMu.Unlock()
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "❌ Логин уже существует."), botMessageIDsByChat)
					break
				}
				pass := generatePassword(10)
				webUsers[login] = pass
				if targetUsername != "" {
					webLinks[strings.ToLower(targetUsername)] = login
				}
				webUsersMu.Unlock()
				saveWebUsers()
				msgWebAdd := tgbotapi.NewMessage(adminID, "✅ Учётная запись Web App создана.\n\nЛогин: `"+login+"`\nПароль: `"+pass+"`")
				msgWebAdd.ParseMode = "Markdown"
				sendAndTrack(bot, msgWebAdd, botMessageIDsByChat)
				if targetUsername != "" {
					var targetID int64
					for id, uname := range allUsers {
						if strings.EqualFold(uname, targetUsername) {
							targetID = id
							break
						}
					}
					if targetID == 0 {
						sendAndTrack(bot, tgbotapi.NewMessage(adminID, "⚠️ Пользователь @"+targetUsername+" не найден в whitelist (`users.json`). Выдайте ему доступ через /grant и попробуйте снова."), botMessageIDsByChat)
						break
					}
					userMsg := tgbotapi.NewMessage(targetID, "🔐 Данные для входа на сайт:\n\nЛогин: `"+login+"`\nПароль: `"+pass+"`\n\nСохраните их в безопасном месте.")
					userMsg.ParseMode = "Markdown"
					if _, err := sendAndTrack(bot, userMsg, botMessageIDsByChat); err != nil {
						sendAndTrack(bot, tgbotapi.NewMessage(adminID, "⚠️ Не удалось отправить данные пользователю @"+targetUsername+"."), botMessageIDsByChat)
					} else {
						sendAndTrack(bot, tgbotapi.NewMessage(adminID, "✅ Данные отправлены пользователю @"+targetUsername+"."), botMessageIDsByChat)
					}
				}

			case "weblist":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ Нет прав."), botMessageIDsByChat)
					break
				}
				webUsersMu.RLock()
				if len(webUsers) == 0 {
					webUsersMu.RUnlock()
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Нет учётных записей Web App."), botMessageIDsByChat)
					break
				}
				var b strings.Builder
				b.WriteString("📋 Учётные записи Web App:\n")
				for l := range webUsers {
					b.WriteString("• " + l + "\n")
				}
				webUsersMu.RUnlock()
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, b.String()), botMessageIDsByChat)

			case "webremove":
				if user.ID != adminID {
					sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ Нет прав."), botMessageIDsByChat)
					break
				}
				login := strings.TrimSpace(strings.Split(args, " ")[0])
				if login == "" {
					sendAndTrack(bot, tgbotapi.NewMessage(adminID, "Использование: /webremove <логин>"), botMessageIDsByChat)
					break
				}
				webUsersMu.Lock()
				delete(webUsers, login)
				webUsersMu.Unlock()
				saveWebUsers()
				sendAndTrack(bot, tgbotapi.NewMessage(adminID, "✅ Доступ к Web App для «"+login+"» отозван."), botMessageIDsByChat)
			}
			continue
		}

		// === Обработка Reply-кнопок ===
		switch text {
		case "🔐 Данные для сайта":
			uname := strings.ToLower(strings.TrimSpace(user.UserName))
			if uname == "" {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ У вашего Telegram-аккаунта нет @username. Напишите администратору, чтобы выдал данные вручную."), botMessageIDsByChat)
				break
			}
			webUsersMu.RLock()
			login, ok := webLinks[uname]
			pass := ""
			if ok {
				pass = webUsers[login]
			}
			webUsersMu.RUnlock()
			if !ok || pass == "" {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "❌ Для вашего аккаунта пока не назначены данные сайта. Обратитесь к администратору."), botMessageIDsByChat)
				break
			}
			out := tgbotapi.NewMessage(msg.Chat.ID, "🔐 Ваши данные для сайта:\n\nЛогин: `"+login+"`\nПароль: `"+pass+"`")
			out.ParseMode = "Markdown"
			sendAndTrack(bot, out, botMessageIDsByChat)

		case "ℹ️ Помощь":
			sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID,
				"Привет! 😎\n\n☎️ Номера — контакты бариста, служб и кофеен\n☕ Зерно — сорта и настройка\n📷 Бот Сёрфа — Web App и QR-код\n✉️ Администратору — написать руководству\n\nЯ здесь, чтобы помочь 💪"), botMessageIDsByChat)

		case "📋 О боте":
			aboutText := "☕ *Surf Coffee Bot*\n\n" +
				"Бот для сотрудников: контакты, информация о зерне, помощник (КБЖУ, графики, рекламации), связь с администрацией.\n\n" +
				"🔄 Главное меню — вернуться к списку разделов\n" +
				"📋 О боте — эта справка"
			msgAbout := tgbotapi.NewMessage(msg.Chat.ID, aboutText)
			msgAbout.ParseMode = "Markdown"
			sendAndTrack(bot, msgAbout, botMessageIDsByChat)

		case "🛡️ Спец Службы":
			inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("Охрана(Виктор)", "phone_Oxrana"),
					tgbotapi.NewInlineKeyboardButtonData("Кондиционер(Ильфир)", "phone_Xolodilnik"),
					tgbotapi.NewInlineKeyboardButtonData("Сантехник(Виктор)", "phone_Santexkin"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("Ледген(Ильдар)", "phone_ledgen"),
					tgbotapi.NewInlineKeyboardButtonData("Электрик(Алмаз)", "phone_Electric"),
					tgbotapi.NewInlineKeyboardButtonData("Мастер(Рафис)", "phone_Master"),
				),
			)

			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери службу, что бы увидеть номер:")
			msgOut.ReplyMarkup = inlineKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📞 Бариста":
			inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("Евгений", "phone_Evgeiny"),
					tgbotapi.NewInlineKeyboardButtonData("Алина Менеджер", "phone_Alina(meng)"),
					tgbotapi.NewInlineKeyboardButtonData("Алина Младшая", "phone_Alina(mlad)"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("Анджелика", "phone_Angelika"),
					tgbotapi.NewInlineKeyboardButtonData("Азалия", "phone_Azalia"),
					tgbotapi.NewInlineKeyboardButtonData("Марсель", "phone_Marsel"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("Настя", "phone_Nastya"),
					tgbotapi.NewInlineKeyboardButtonData("Айнур", "phone_Ainyr"),
					tgbotapi.NewInlineKeyboardButtonData("Леонид", "phone_Leonid"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("Альбина", "phone_Albina"),
					tgbotapi.NewInlineKeyboardButtonData("Алина Старшая", "phone_Alina(zel)"),
					tgbotapi.NewInlineKeyboardButtonData("Серёжа", "phone_Sereja"),
				),
			)

			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери бариста, что бы увидеть номер:")
			msgOut.ReplyMarkup = inlineKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)

		case "☕ Кофейни Surf":
			inlineKeyboard := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("xSaveIn", "phone_xSaveIn"),
					tgbotapi.NewInlineKeyboardButtonData("xMuses", "phone_xMuses"),
					tgbotapi.NewInlineKeyboardButtonData("xLovers", "phone_xLovers"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("xKremlin", "phone_xKremlin"),
					tgbotapi.NewInlineKeyboardButtonData("xJoe", "phone_xJoe"),
					tgbotapi.NewInlineKeyboardButtonData("xItPark", "phone_xItPark"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("xIva", "phone_xIva"),
					tgbotapi.NewInlineKeyboardButtonData("xCult", "phone_xCult"),
					tgbotapi.NewInlineKeyboardButtonData("xLetskoy", "phone_xLetskoy"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("xUnofficial", "phone_xUnofficial"),
					tgbotapi.NewInlineKeyboardButtonData("xInside", "phone_xInside"),
					tgbotapi.NewInlineKeyboardButtonData("xKasatka", "phone_xKasatka"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("xMega", "phone_xMega"),
					tgbotapi.NewInlineKeyboardButtonData("xSuite", "phone_xSuite"),
					tgbotapi.NewInlineKeyboardButtonData("xKazanMall", "phone_xKazanMall"),
				),
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("xArch", "phone_xArch"),
					tgbotapi.NewInlineKeyboardButtonData("xNokka", "phone_xNokka"),
				),
			)

			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери кофейню, чтобы увидеть номер:")
			msgOut.ReplyMarkup = inlineKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📷 Бот Сёрфа":
			// Создаем WebApp кнопку для открытия мини-приложения
			webAppButton := tgbotapi.NewKeyboardButtonWebApp("🚀 Открыть Web App", tgbotapi.WebAppInfo{URL: webAppURL})
			webAppKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(webAppButton),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📷 Показать QR-код"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "📱 *Доступ к боту Сёрфа:*\n\n• Нажми '🚀 Открыть Web App' для запуска мини-приложения\n• Или '📷 Показать QR-код' для сканирования")
			msgOut.ParseMode = "Markdown"
			msgOut.ReplyMarkup = webAppKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)

		case "📷 Показать QR-код":
			file, err := os.Open("qr.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение QR."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "qr.jpg", Reader: file})
			photo.Caption = "Вот твой QR-код 📷\n\nТакже ты можешь открыть мини-приложение через кнопку '🚀 Открыть Web App'"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📞 Номера":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📞 Бариста"),
					tgbotapi.NewKeyboardButton("🛡️ Спец Службы"),
					tgbotapi.NewKeyboardButton("☕ Кофейни Surf"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "Выбери номер, который тебя интересует ")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		// === Blend меню ===
		case "📦 Все о зерне":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Зерно"),
					tgbotapi.NewKeyboardButton("📦 Настройка"),
				),

				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери интересующий тебя Раздел:")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)

		case "📦 Настройка":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("☕ Espresso"),
					tgbotapi.NewKeyboardButton("☕ Ph"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("☕ Descriptors"),
					tgbotapi.NewKeyboardButton("☕ Extraction"),
					tgbotapi.NewKeyboardButton("☕ Filter"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔄 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери интересующий тебя Раздел:")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Espresso":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Blend#2"),
					tgbotapi.NewKeyboardButton("📦 Blend#3"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Blend#4"),
					tgbotapi.NewKeyboardButton("📦 Blend#5"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("☕ Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери интересующий тебя Раздел:")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Filter":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Africa"),
					tgbotapi.NewKeyboardButton("📦 America"),
					tgbotapi.NewKeyboardButton("📦 Ethiopia Solomo"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Twin Fin"),
					tgbotapi.NewKeyboardButton("📦 Decaf"),
					tgbotapi.NewKeyboardButton("📦 Ethiopia Uraga"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Malawi Domira Bay"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("☕ Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери интересующий тебя Раздел:")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Зерно":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Espresso"),
					tgbotapi.NewKeyboardButton("📦 Filter"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔄 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери интересующий тебя Раздел:")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "💼 Помощник":
			blendKeyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Кбжу"),
					tgbotapi.NewKeyboardButton("📦 Состав десертов"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 График работы"),
					tgbotapi.NewKeyboardButton("📦 Рекламация"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "☕ Выбери интересующий тебя Раздел:")
			msgOut.ReplyMarkup = blendKeyboard
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Кбжу":
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, `Кбжу десертов и напитков: <span class="tg-spoiler">https://docs.google.com/spreadsheets/d/1WO1vzivTrDq2E7qVbyXkZWUaQty_3424uGM8uVspLWI/edit?usp=drivesdk</span>`)
			msgOut.ParseMode = "HTML"
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Состав десертов":
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, `Состав десертов и напитков: <span class="tg-spoiler">https://docs.google.com/spreadsheets/d/1osNe5k1iwYFbcvX_aU3B01YOwaCub28ThB73003OuBg/edit?usp=drivesdk</span>`)
			msgOut.ParseMode = "HTML"
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 График работы":
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, `График работы: <span class="tg-spoiler">https://docs.google.com/spreadsheets/d/1PyP-_4pgiz7Ok6eqfk2YU6yrhpkO2snUN1wZ7FqMMNI/edit?usp=drivesdk</span>`)
			msgOut.ParseMode = "HTML"
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Рекламация":
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, `Подать рекламацию: <span class="tg-spoiler">https://library.surfcoffee.ru/trinity-harrogate-form/</span>`)
			msgOut.ParseMode = "HTML"
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "📦 Twin Fin":
			file, err := os.Open("zerno/TwinFin.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение TwinFin."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/TwinFin.jpg", Reader: file})
			photo.Caption = "📦 TwinFin — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Africa":
			file, err := os.Open("zerno/Africa.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Africa."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/Africa.jpg", Reader: file})
			photo.Caption = "📦 Africa — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "📦 America":
			file, err := os.Open("zerno/America.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение America."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/America.jpg", Reader: file})
			photo.Caption = "📦 America — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Malawi Domira Bay":
			file, err := os.Open("zerno/MalawiDomiraBay.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение MalawiDomiraBay."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/MalawiDomiraBay.jpg", Reader: file})
			photo.Caption = "📦 Malawi Domira Bay — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Decaf":
			file, err := os.Open("zerno/Decaf.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Decaf."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/Decaf.jpg", Reader: file})
			photo.Caption = "📦 Decaf — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Ethiopia Uraga":
			file, err := os.Open("zerno/EthiopiaUraga.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение EthiopiaUraga."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/EthiopiaUraga.jpg", Reader: file})
			photo.Caption = "📦 Ethiopia Uraga — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Ethiopia Solomo":
			file, err := os.Open("zerno/EthiopiaUragaSolomo.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение EthiopiaUragaSolomo."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/EthiopiaUragaSolomo.jpg", Reader: file})
			photo.Caption = "📦 Ethiopia Uraga Solomo — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

			////////////////////////////////////////////////
		case "📦 Blend#2":
			file, err := os.Open("zerno/blend2.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Blend#2."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/blend2.jpg", Reader: file})
			photo.Caption = "📦 Blend#2 — мягкий шоколадно-ореховый вкус ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Blend#3":
			file, err := os.Open("zerno/blend3.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Blend#3."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/blend3.jpg", Reader: file})
			photo.Caption = "📦 Blend#3 — насыщенный вкус с нотами какао и карамели."
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "📦 Blend#5":
			file, err := os.Open("zerno/blend5.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Blend#5."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/blend5.jpg", Reader: file})
			photo.Caption = "📦 Blend#5 — яркий, фруктово-ягодный профиль с лёгкой цитрусовой кислинкой."
			sendAndTrack(bot, photo, botMessageIDsByChat)

		case "📦 Blend#4":
			file, err := os.Open("zerno/blend4.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Blend#4."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "zerno/blend4.jpg", Reader: file})
			photo.Caption = "📦 Blend#4 — фруктово-цитрусовый профиль ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "☕ Espresso":
			file, err := os.Open("helpzerno/Espresso.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Espresso."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "helpzerno/Espresso.jpg", Reader: file})
			photo.Caption = "📦 Вот таблица, что бы легче настоить Эспрессо! ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "☕ Extraction":
			file, err := os.Open("helpzerno/Extraction.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Extraction."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "helpzerno/Extraction.jpg", Reader: file})
			photo.Caption = "📦 Вот таблица, что бы легче было понять работу экстракцию кофе! ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "☕ Filter":
			file, err := os.Open("helpzerno/filter.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Filter."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "helpzerno/filter.jpg", Reader: file})
			photo.Caption = "📦 Вот таблица, что бы легче сделать фильтр! ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "☕ Ph":
			file, err := os.Open("helpzerno/Ph.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Ph."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "helpzerno/Ph.jpg", Reader: file})
			photo.Caption = "📦 Уровень Ph для идеальной настройки. ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "☕ Descriptors":
			file, err := os.Open("helpzerno/Descriptors.jpg")
			if err != nil {
				sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "⚠️ Не удалось найти изображение Descriptors."), botMessageIDsByChat)
				break
			}
			defer file.Close()
			photo := tgbotapi.NewPhoto(msg.Chat.ID, tgbotapi.FileReader{Name: "helpzerno/Descriptors.jpg", Reader: file})
			photo.Caption = "📦 Таблица всех основных дескрипторов. ☕"
			sendAndTrack(bot, photo, botMessageIDsByChat)
		case "🔙 Назад в меню", "🔄 Главное меню":
			mainMenu := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("ℹ️ Помощь"),
					tgbotapi.NewKeyboardButton("📞 Номера"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("💼 Помощник"),
					tgbotapi.NewKeyboardButton("📦 Все о зерне"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📷 Бот Сёрфа"),
					tgbotapi.NewKeyboardButton("✉️ Администратору"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔐 Данные для сайта"),
				),
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔄 Главное меню"),
					tgbotapi.NewKeyboardButton("📋 О боте"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "⬅️ Главное меню")
			msgOut.ReplyMarkup = mainMenu
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "🔄 Назад в меню":
			mainMenu := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Зерно"),
					tgbotapi.NewKeyboardButton("📦 Настройка"),
				),

				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔙 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "⬅️ Возврат в главное меню:")
			msgOut.ReplyMarkup = mainMenu
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "☕ Назад в меню":
			mainMenu := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("📦 Espresso"),
					tgbotapi.NewKeyboardButton("📦 Filter"),
				),

				tgbotapi.NewKeyboardButtonRow(
					tgbotapi.NewKeyboardButton("🔄 Назад в меню"),
				),
			)
			msgOut := tgbotapi.NewMessage(msg.Chat.ID, "⬅️ Возврат в главное меню:")
			msgOut.ReplyMarkup = mainMenu
			sendAndTrack(bot, msgOut, botMessageIDsByChat)
		case "✉️ Сообщение Администратору", "✉️ Администратору":
			waitingForAdminMessage[user.ID] = true
			sendAndTrack(bot, tgbotapi.NewMessage(msg.Chat.ID, "✉️ Напиши сообщение для администратора:"), botMessageIDsByChat)
		}
	}
}
