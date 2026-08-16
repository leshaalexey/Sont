<!--
  Вкладка подписок: список ключей и добавление нового.

  Карточки «текущей подписки» здесь больше нет. Ключ и подписка — одно и то
  же, и карточка пересказывала первую строку списка ещё раз, крупнее: то же
  имя, тот же срок, то же число серверов. Разбирать, чем «текущая» отличается
  от строки прямо под ней, приходилось каждый раз заново — а отличалась она
  только размером.
-->
<script>
  import Section from "../Section.svelte";
  import BoxedRow from "../BoxedRow.svelte";
  import Button from "../Button.svelte";
  import KeyList from "../KeyList.svelte";
  import { status, act, say } from "../daemon.js";
  import { t } from "../i18n.js";

  let url = $state("");

  const count = $derived($status?.subscriptions?.length ?? 0);

  async function add() {
    const value = url.trim();
    if (!value) return;
    await act("add_subscription", { url: value });
    url = "";
    say($t("msg.added"));
  }
</script>

<Section title={$t("sec.saved")} aside={count > 0 ? `${count} ${$t("msg.keys")}` : null} />

{#if count === 0}
  <p class="empty">{$t("msg.noKeys")}</p>
{:else}
  <KeyList />
{/if}

<BoxedRow dashed>
  <input
    class="field"
    type="text"
    spellcheck="false"
    placeholder={$t("key.placeholder")}
    bind:value={url}
    onkeydown={(e) => e.key === "Enter" && add()}
  />
  <Button onclick={add}>{$t("btn.add")}</Button>
</BoxedRow>

<style>
  .empty {
    margin: 4px 0 0;
    font-size: 9px;
    font-weight: 350;
    line-height: 130%;
    color: var(--dim-4);
  }

  /* Плейсхолдер начинается у левого края поля: пустой подписи перед ним
     больше нет, а собственных отступов у поля не заведено — они заданы
     рамкой снаружи, и удваивать их незачем. */
  .field {
    flex: 1;
    min-width: 0;
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--cream);
    font-family: inherit;
    font-size: 10px;
    font-weight: 350;
    line-height: 100%;
    outline: none;
    user-select: text;
    -webkit-user-select: text;
  }

  .field::placeholder {
    color: rgba(244, 237, 229, 0.45);
  }
</style>
