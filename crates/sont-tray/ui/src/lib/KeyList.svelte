<!--
  Ключи подписок. Серверы из всех идут в общий выбор — это не список «какой
  включён», а список «какие есть».

  Строка несёт всё, что о ключе известно: маску, число серверов, остаток
  срока и израсходованный трафик, если у подписки есть лимит. Раньше это
  лежало в отдельной карточке над списком и относилось всегда к первому
  ключу; здесь каждая строка говорит сама за себя.
-->
<script>
  import { status, ask, act, say } from "./daemon.js";
  import { t } from "./i18n.js";
  import { remaining, bytes, usedPercent } from "./format.js";

  const subs = $derived($status?.subscriptions ?? []);

  /**
   * Какой ключ только что скопирован.
   *
   * Ответ показывает сама кнопка, а не сообщение внизу окна. Плашка отвечала
   * не там, где спрашивали: взгляд в момент нажатия на кнопке, а подтверждение
   * появлялось в другом конце панели — и при нескольких ключах не говорило,
   * какой именно скопирован.
   */
  let copied = $state(null);
  let timer;

  /**
   * Настоящий ключ уходит наружу только здесь и только по нажатию —
   * отдельным запросом к демону, который иначе его не отдаёт вовсе. В списке
   * лежит одна маска.
   */
  async function copy(sub) {
    const key = await ask("reveal_subscription", { id: sub.id });
    if (!key) return;

    // Запись в буфер отказывает — окно не в фокусе, система не дала прав, —
    // и отказ надо показать. Молчание тут хуже всего: пользователь уверен,
    // что ключ у него, идёт вставлять и получает чужой текст недельной
    // давности.
    try {
      await navigator.clipboard.writeText(key);
    } catch (e) {
      say(String(e), true);
      return;
    }

    copied = sub.id;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = null), 1600);
  }

  function traffic(info) {
    const percent = usedPercent(info);
    if (percent == null) return null;
    return `${bytes((info.upload ?? 0) + (info.download ?? 0))} / ${bytes(info.total)}`;
  }
</script>

<div class="list">
  {#each subs as sub (sub.id)}
    {@const used = traffic(sub.info)}
    <div class="item">
      <div class="text">
        <span class="name">{sub.masked_url}</span>
        <span class="meta">
          {sub.info?.server_count ?? 0} · {remaining(sub.info?.expires_at_unix, $t("msg.forever"))}{used
            ? ` · ${used}`
            : ""}
        </span>
        {#if usedPercent(sub.info) != null}
          <span class="meter"><span class="fill" style="width:{usedPercent(sub.info)}%"></span></span>
        {/if}
      </div>

      <span class="actions">
        <!--
          Обе подписи лежат друг на друге, и кнопка всегда шириной с более
          длинную. Иначе при нажатии «Копировать» превращается в
          «Скопировано», кнопка раздаётся вширь и толкает соседнюю — вместо
          подтверждения выходит скачок раскладки. Ширина считается сама, так
          что перевод на любой язык её не сломает.
        -->
        <button class="act" class:done={copied === sub.id} onclick={() => copy(sub)}>
          <span class="swap">
            <span class:muted={copied === sub.id}>{$t("btn.copy")}</span>
            <span class:muted={copied !== sub.id}>{$t("btn.copied")}</span>
          </span>
        </button>
        <button class="act" onclick={() => act("remove_subscription", { id: sub.id })}>
          {$t("btn.remove")}
        </button>
      </span>
    </div>
  {/each}
</div>

<style>
  .list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    border: 0.5px solid var(--line-strong);
    border-radius: 5px;
    padding: 7px 7px 7px 9px;
  }

  .text {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .name {
    font-size: 9px;
    font-weight: 500;
    line-height: 125%;
    color: var(--cream);
  }

  .meta {
    font-size: 8px;
    font-weight: 350;
    line-height: 125%;
    color: rgba(244, 237, 229, 0.55);
  }

  /* Полоска расхода рисуется только у подписок с лимитом: у безлимитной ей
     нечего показывать, а пустой жёлоб читается как «ничего не потрачено». */
  .meter {
    position: relative;
    display: block;
    height: 2px;
    margin-top: 1px;
    border-radius: 2px;
    background: rgba(244, 237, 229, 0.15);
    overflow: hidden;
  }
  .fill {
    position: absolute;
    inset: 0 auto 0 0;
    background: var(--accent);
    border-radius: 2px;
  }

  .actions {
    flex: none;
    display: flex;
    gap: 4px;
  }

  .act {
    padding: 4px 6px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    box-shadow: inset 0 0 0 0.5px rgba(244, 237, 229, 0.4);
    color: var(--dim-1);
    font-family: inherit;
    font-size: 8px;
    font-weight: 500;
    line-height: 100%;
    white-space: nowrap;
    cursor: pointer;
    transition:
      background 260ms var(--ease),
      color 260ms var(--ease),
      box-shadow 260ms var(--ease);
  }

  /*
   * Подтверждение — заливка акцентом на полторы секунды.
   *
   * Возврат идёт тем же переходом, что и заливка: мгновенное «погасло»
   * читалось бы вторым событием, хотя ничего не произошло — просто прошло
   * время.
   */
  .done {
    background: var(--accent);
    box-shadow: inset 0 0 0 0.5px var(--accent);
    color: var(--on-accent);
    /* Светлое на тёмном кажется жирнее — ступень вниз выравнивает. */
    font-weight: calc(500 + var(--on-accent-weight));
  }

  /* Обе подписи в одной ячейке сетки: место занимают обе, видна одна. */
  .swap {
    display: grid;
  }
  .swap > span {
    grid-area: 1 / 1;
  }
  .muted {
    visibility: hidden;
  }
</style>
