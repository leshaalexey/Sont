import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Сборка идёт в `dist`, откуда её берёт Tauri. Пути относительные: окно
// открывается не по http, а по внутреннему протоколу, и абсолютный `/assets`
// там не разрешается.
export default defineConfig({
  plugins: [svelte()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // WebView2 на поддерживаемых Windows — это свежий Chromium; занижать
    // цель незачем, а лишние полифилы только раздувают бандл.
    target: "chrome110",
    // Карты кода в готовом окне не нужны, а в отладочной сборке помогают.
    sourcemap: process.env.TAURI_ENV_DEBUG === "true",
    minify: process.env.TAURI_ENV_DEBUG === "true" ? false : "esbuild",
  },
  // Tauri сам следит за консолью; очистка экрана прячет его сообщения.
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
});
