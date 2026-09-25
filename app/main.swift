// Нативная обёртка морды: обычное macOS-приложение с окном, иконкой в Dock и
// Cmd+Tab, без браузерной обвязки. Внутри — WKWebView, который показывает ту же
// морду (ui_server.py на 127.0.0.1:7890).
//
// Почему так, а не Electron/Tauri: у проекта правило «никаких зависимостей сверх
// системных». WKWebView и AppKit — часть macOS, swiftc — часть Xcode CLT,
// которая тут и так нужна для codesign в bundle_bin.py.
//
// Сервер морды поднимается самим приложением как дочерний процесс и гасится при
// выходе: иначе после закрытия окна ui_server.py остаётся висеть в фоне, и в
// следующий раз порт занят (ловилось на живом запуске).

import AppKit
import WebKit

let ПОРТ = 7890
let АДРЕС = "http://127.0.0.1:\(ПОРТ)/"

final class Приложение: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    var окно: NSWindow!
    var веб: WKWebView!
    var сервер: Process?
    /// Корень репозитория кладётся в Info.plist при сборке — так .app можно
    /// таскать куда угодно, он всё равно знает, где лежит ui_server.py.
    let корень = Bundle.main.object(forInfoDictionaryKey: "VPNCTLRepoDir") as? String ?? ""

    func applicationDidFinishLaunching(_ notification: Notification) {
        собратьМеню()
        поднятьСервер()
        собратьОкно()
        загрузитьСПовторами(осталось: 20)
    }

    /// Без своего меню в WKWebView не работают даже Cmd+C/Cmd+V/Cmd+Q — эти
    /// комбинации у AppKit разбираются через пункты меню с тем же key equivalent,
    /// а не перехватываются WebView-ом сами по себе. Без Cmd+R страницу пришлось
    /// бы обновлять полным перезапуском приложения при каждой правке морды.
    func собратьМеню() {
        let главное = NSMenu()

        let app = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Выйти из vpnctl", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        app.submenu = appMenu
        главное.addItem(app)

        let правка = NSMenuItem()
        let правкаMenu = NSMenu(title: "Правка")
        правкаMenu.addItem(withTitle: "Отменить", action: Selector(("undo:")), keyEquivalent: "z")
        правкаMenu.addItem(withTitle: "Повторить", action: Selector(("redo:")), keyEquivalent: "Z")
        правкаMenu.addItem(.separator())
        правкаMenu.addItem(withTitle: "Вырезать", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        правкаMenu.addItem(withTitle: "Копировать", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        правкаMenu.addItem(withTitle: "Вставить", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        правкаMenu.addItem(withTitle: "Выделить всё", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        правка.submenu = правкаMenu
        главное.addItem(правка)

        let вид = NSMenuItem()
        let видMenu = NSMenu(title: "Вид")
        видMenu.addItem(withTitle: "Обновить страницу", action: #selector(обновитьСтраницу), keyEquivalent: "r")
        вид.submenu = видMenu
        главное.addItem(вид)

        let окноПункт = NSMenuItem()
        let окноMenu = NSMenu(title: "Окно")
        окноMenu.addItem(withTitle: "Свернуть", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        окноMenu.addItem(withTitle: "Закрыть", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        окноПункт.submenu = окноMenu
        главное.addItem(окноПункт)

        NSApp.mainMenu = главное
    }

    @objc func обновитьСтраницу() {
        веб?.reload()
    }

    /// Морда должна работать и когда её запустили из терминала (`./vpn морда`),
    /// и когда открыли приложением. Поэтому сначала проверяем, не отвечает ли
    /// уже кто-то на порту, и только потом поднимаем свой процесс.
    func поднятьСервер() {
        if портОтвечает() { return }
        let скрипт = (корень as NSString).appendingPathComponent("ui_server.py")
        guard FileManager.default.fileExists(atPath: скрипт) else { return }
        let процесс = Process()
        процесс.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        процесс.arguments = [скрипт]
        процесс.currentDirectoryURL = URL(fileURLWithPath: корень)
        процесс.standardOutput = FileHandle.nullDevice
        процесс.standardError = FileHandle.nullDevice
        try? процесс.run()
        сервер = процесс
    }

    func портОтвечает() -> Bool {
        guard let url = URL(string: АДРЕС) else { return false }
        var запрос = URLRequest(url: url)
        запрос.timeoutInterval = 0.6
        let семафор = DispatchSemaphore(value: 0)
        var живой = false
        URLSession.shared.dataTask(with: запрос) { _, ответ, _ in
            живой = (ответ as? HTTPURLResponse)?.statusCode == 200
            семафор.signal()
        }.resume()
        _ = семафор.wait(timeout: .now() + 1.0)
        return живой
    }

    func собратьОкно() {
        окно = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 780),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered, defer: false)
        окно.title = "vpnctl"
        окно.center()
        окно.setFrameAutosaveName("vpnctl-главное")
        // Без этого окно остаётся на том рабочем столе (Space), где приложение
        // впервые запустилось: переключаешься на другой — приложение активно,
        // в строке меню его имя, а окна нет. Ловилось на живом запуске.
        окно.collectionBehavior = [.moveToActiveSpace, .fullScreenPrimary]

        let настройки = WKWebViewConfiguration()
        веб = WKWebView(frame: окно.contentView!.bounds, configuration: настройки)
        веб.autoresizingMask = [.width, .height]
        веб.navigationDelegate = self
        окно.contentView!.addSubview(веб)
        окно.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Сервер поднимается доли секунды, но не мгновенно — без повторов первое
    /// открытие показывало бы «не удалось подключиться».
    func загрузитьСПовторами(осталось: Int) {
        if портОтвечает() {
            веб.load(URLRequest(url: URL(string: АДРЕС)!))
            return
        }
        guard осталось > 0 else {
            показатьОшибку()
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            self.загрузитьСПовторами(осталось: осталось - 1)
        }
    }

    func показатьОшибку() {
        let html = """
        <html><body style="font-family:-apple-system;background:#101216;color:#e7e9ee;
        padding:3rem;line-height:1.5">
        <h2>Морда не поднялась</h2>
        <p>Не отвечает <code>\(АДРЕС)</code>.</p>
        <p>Запусти вручную и посмотри, что скажет:</p>
        <pre style="background:#191c22;padding:1rem;border-radius:8px">cd \(корень)<br>/usr/bin/python3 ui_server.py</pre>
        </body></html>
        """
        веб.loadHTMLString(html, baseURL: nil)
    }

    // Закрыли окно — закрыли приложение (это однооконная утилита, держать её
    // в Dock без окна незачем).
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    /// Клик по иконке в Dock у уже запущенного приложения: без этого окно не
    /// показывается заново (macOS сам его не поднимает), приложение просто
    /// становится активным с пустым экраном.
    func applicationShouldHandleReopen(_ app: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows { окно?.makeKeyAndOrderFront(nil) }
        NSApp.activate(ignoringOtherApps: true)
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        сервер?.terminate()
    }
}

let приложение = NSApplication.shared
let делегат = Приложение()
приложение.delegate = делегат
приложение.setActivationPolicy(.regular)
приложение.run()
