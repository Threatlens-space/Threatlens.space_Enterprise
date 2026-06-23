(function () {
  const MESSAGE_TYPE = "threatlens:get-time-since-last-click";
  let lastHumanClickAt = 0;

  function getElementTarget(target) {
    if (!target) return null;
    if (target.nodeType === Node.ELEMENT_NODE) return target;
    return target.parentElement || null;
  }

  document.addEventListener("click", (event) => {
    if (!event.isTrusted) return;

    const target = getElementTarget(event.target);
    if (target && target.closest("a, button")) {
      lastHumanClickAt = Date.now();
    }
  }, true);

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== MESSAGE_TYPE) {
      return false;
    }

    sendResponse({
      ok: true,
      lastHumanClickAt: lastHumanClickAt || null,
      timeSinceLastClick: lastHumanClickAt ? Date.now() - lastHumanClickAt : null
    });
    return false;
  });
})();
