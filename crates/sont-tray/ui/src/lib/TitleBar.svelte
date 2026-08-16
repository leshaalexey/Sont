<!--
  Шапка окна: состояние, сервер и задержка.

  Времени работы здесь больше нет. Оно отвечало на вопрос, который в трее не
  задают: сколько именно секунд держится туннель, важно раз в жизни, а место
  занимало постоянно — и отбирало его у имени сервера, которому места как раз
  не хватало.

  Строка целиком — сведения, а не орган управления. Соединением здесь никто не
  щёлкает: демон поднимает его сам при запуске и сам пересобирает, когда
  меняются настройки. Плашка, похожая на кнопку, обещала бы обратное — что
  соединение держится нажатием, — и первый же случай, когда демон
  переподключился без спроса, выглядел бы поломкой.

  Раскладка — обычный flex. Абсолютные координаты макета держались на ширине
  окна и ломались от одной правки; вырез между плашками при этом никуда не
  делся, он просто переехал внутрь плашки, к её левому краю.
-->
<script>
  import Mascot from "./Mascot.svelte";
  import MascotOffline from "./MascotOffline.svelte";
  import Notch from "./Notch.svelte";
  import { status } from "./daemon.js";
  import { t } from "./i18n.js";

  // `kind` приходит из демона отдельным полем: `state` сериализуется с тегом
  // и в JSON выглядит как `state.state`, читать это из разметки незачем.
  const kind = $derived($status?.kind ?? "disconnected");

  // Маскот бодрствует, только пока соединение работает. Промежуточные
  // состояния показываем как нерабочие: пока туннель не поднят, трафик через
  // него не идёт, и рисовать бодрого маскота значит обещать несуществующее.
  const alive = $derived(kind === "connected");

  /*
   * Имя сервера как есть.
   *
   * Раньше отсюда пытались выделить город: провайдеры называют серверы как
   * придётся, и «🇳🇱 Netherlands, Amsterdam #3» хотелось свести к
   * «Amsterdam». Догадка работала на аккуратных именах и врала на всех
   * прочих — в плашке оказывался кусок тарифа, номер узла или обрывок
   * протокола. Непонятная строка вместо имени хуже обрезанного имени:
   * обрезанное хотя бы начинается с того, что написал провайдер.
   */
  const where = $derived($status?.server_name ?? "—");
  const ping = $derived($status?.rtt_ms != null ? `${$status.rtt_ms} ms` : "—");
</script>

<header class="titlebar" data-tauri-drag-region>
  <div class="row">
    <div class="pill state" data-state={kind}>{$t(`state.${kind}`)}</div>

    <div class="pill server"><Notch inner /><span class="clip">{where}</span></div>
    <div class="pill ping tnum"><Notch inner />{ping}</div>
  </div>

  <div class="mascot-slot" class:offline={!alive}>
    {#if alive}<Mascot />{:else}<MascotOffline />{/if}
  </div>
</header>

<style>
  .titlebar {
    position: absolute;
    inset: 0 0 auto 0;
    height: 26px;
    overflow: hidden;
    background: var(--bg-sunken);
    border-bottom: 0.5px solid var(--hair);
  }

  /* Справа оставлено место маскоту: он живёт своим слоем, чтобы плашки не
     ужимались вокруг рисунка переменной ширины. */
  .row {
    position: absolute;
    left: 5px;
    right: 40px;
    top: 5px;
    height: 15px;
    display: flex;
    gap: 2px;
  }

  .pill {
    position: relative;
    height: 15px;
    padding: 0;
    border: 0;
    border-radius: 2px;
    background: var(--accent);
    color: var(--on-accent);
    font-family: inherit;
    font-size: 8px;
    font-weight: 500;
    line-height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    white-space: nowrap;
  }

  /*
   * Обрезка живёт на тексте, а не на плашке.
   *
   * Вырез между плашками нарисован фигурой, выступающей за левый край на
   * четыре точки, и `overflow: hidden` на самой плашке срезал его начисто —
   * плашки переставали быть сцеплёнными и превращались в отдельные
   * прямоугольники.
   */

  /* Состояние и задержка — фиксированной ширины, имя сервера забирает всё
     остальное: имён короче «Frankfurt» почти не бывает, а длиннее бывает
     сколько угодно. */
  .state {
    flex: 0 0 66px;
  }
  .server {
    flex: 1 1 auto;
    min-width: 0;
  }
  .ping {
    flex: 0 0 40px;
  }

  /* Не влезло — обрезаем многоточием, а не выталкиваем соседей. */
  .clip {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    padding: 0 3px;
  }

  /*
   * Плашка всегда светлая. Затемнение при отключении читалось как
   * неисправность самой плашки, а не как состояние связи, — а состояние и
   * так написано словом. Разница между «отключено» и «разорвано» тоже в
   * словах: первое сделал пользователь, второе случилось само.
   */

  .mascot-slot {
    position: absolute;
    right: 12px;
    top: 11px;
    color: var(--cream);
  }
  /* Рисунок оборванной связи шире и ниже — выравниваем по той же строке. */
  .offline {
    top: 17px;
  }
</style>
