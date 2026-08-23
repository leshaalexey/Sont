# Окружение сборки для NixOS.
#
# # Зачем файл в репозитории
#
# На прочих системах зависимости ставятся пакетным менеджером один раз и живут
# в системе. NixOS так не умеет и не должен: там окружение описывается вместе с
# проектом, иначе «у меня собирается, а у тебя нет» становится нормой. Этот
# файл — и есть описание.
#
# # Как пользоваться
#
#     nix-shell            # входит в оболочку со всем нужным
#     cargo build --release -p sont-daemon
#
# Флейки не нужны: `nix-shell` работает и на флейковой конфигурации.

{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  # Инструменты, которые запускаются при сборке.
  #
  # `nodejs` здесь не по недоразумению: сборочный скрипт трея сам вызывает
  # `npm run build`, чтобы разметка и бинарь не расходились. Собираете только
  # демон — узел всё равно не понадобится, но и не помешает.
  nativeBuildInputs = with pkgs; [
    cargo
    rustc
    pkg-config
    nodejs
  ];

  # Библиотеки, к которым линкуется трей.
  #
  # Демону из этого списка не нужно ничего: он на чистом Rust с rustls, без
  # единой системной библиотеки. Всё перечисленное — цена окна: Tauri на Linux
  # это WebKitGTK, а тот тянет за собой половину GNOME.
  buildInputs = with pkgs; [
    webkitgtk_4_1
    gtk3
    libsoup_3
    glib-networking # без него внутри окна не работает TLS
    libayatana-appindicator # значок в трее
    librsvg
    cairo
    pango
    gdk-pixbuf
    atk
    glib
    gsettings-desktop-schemas
  ];

  shellHook = ''
    # GTK ищет схемы настроек и значки по этим путям. Вне nix-shell их ставит
    # обёртка пакета, а здесь обёртки нет — и окно молча падает при запуске,
    # не найдя схему.
    export XDG_DATA_DIRS="${pkgs.gsettings-desktop-schemas}/share/gsettings-schemas/${pkgs.gsettings-desktop-schemas.name}:${pkgs.gtk3}/share/gsettings-schemas/${pkgs.gtk3.name}:$XDG_DATA_DIRS"

    # Модули glib для TLS: без них WebKit открывает страницы по http и молчит
    # по https.
    export GIO_EXTRA_MODULES="${pkgs.glib-networking}/lib/gio/modules"

    # Отключение dmabuf в WebKit.
    #
    # На большинстве драйверов Linux WebKitGTK 2.4x с dmabuf показывает пустое
    # белое окно вместо страницы. Диагностировать это изнутри невозможно —
    # ошибок нет, просто пусто, — поэтому проще выключить сразу.
    export WEBKIT_DISABLE_DMABUF_RENDERER=1

    echo "Окружение Sont готово."
    echo "  демон:  cargo build --release -p sont-daemon"
    echo "  окно:   cargo build --release -p sont-tray"
  '';
}
