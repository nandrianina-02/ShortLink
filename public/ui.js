/* Fenêtre de confirmation, messages courts et copie dans le presse-papiers.
   ask({ title, message, confirm, danger, input }) -> Promise<true|false> (ou le texte saisi / null si input)
   toast(texte, "err"?)   copyText(texte) -> Promise */
(function () {
  var dlg, region, done, opts = {};
  var reduce = function () { return window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches; };
  window.reduceMotion = reduce;

  /* Fermeture animée de toutes les fenêtres <dialog> : on joue l'animation .closing puis on ferme vraiment. */
  if (window.HTMLDialogElement) {
    var proto = HTMLDialogElement.prototype, nativeClose = proto.close, nativeShow = proto.showModal;
    var stop = function (d) { clearTimeout(d._closing); d._closing = 0; d.classList.remove("closing"); };
    proto.close = function () {
      var d = this, args = arguments;
      if (!d.open || d._closing || reduce()) { if (d._closing) stop(d); return nativeClose.apply(d, args); }
      d.classList.add("closing");
      d._closing = setTimeout(function () { stop(d); nativeClose.apply(d, args); }, 150);
    };
    proto.showModal = function () {
      if (this._closing) { stop(this); if (this.open) return; }
      return nativeShow.apply(this, arguments);
    };
    // Échap passe aussi par la fermeture animée
    document.addEventListener("cancel", function (e) {
      if (e.target instanceof HTMLDialogElement && !reduce()) { e.preventDefault(); e.target.close(); }
    }, true);
  }

  // Compteur animé : fait défiler un nombre jusqu'à sa nouvelle valeur
  window.countTo = function (el, to) {
    var from = Number(el.dataset.n || 0);
    el.dataset.n = to;
    if (from === to) { el.textContent = to; return; }
    if (from) { el.classList.add("bump"); setTimeout(function () { el.classList.remove("bump"); }, 600); }
    if (reduce()) { el.textContent = to; return; }
    var t0 = performance.now(), dur = 700;
    (function tick(t) {
      var k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
      el.textContent = Math.round(from + (to - from) * e);
      if (k < 1) requestAnimationFrame(tick);
    })(t0);
  };

  // Joue l'animation de sortie d'un élément avant de le retirer
  window.animateOut = function (el) {
    return new Promise(function (resolve) {
      if (!el || reduce()) return resolve();
      el.classList.add("leaving");
      setTimeout(resolve, 300);
    });
  };

  function build() {
    if (dlg) return;
    dlg = document.createElement("dialog");
    dlg.className = "ask-dlg";
    dlg.setAttribute("aria-labelledby", "ask-title");
    dlg.setAttribute("aria-describedby", "ask-msg");
    dlg.innerHTML =
      '<form method="dialog" class="dlg-body">' +
        '<h2 id="ask-title"></h2>' +
        '<p id="ask-msg" class="dlg-msg"></p>' +
        '<div data-r="field" hidden><label for="ask-input"></label><textarea id="ask-input" maxlength="200" rows="3"></textarea></div>' +
        '<div class="dlg-actions">' +
          '<button type="button" class="ghost" data-r="cancel">Annuler</button>' +
          '<button type="submit" value="ok" data-r="ok">Confirmer</button>' +
        '</div>' +
      '</form>';
    document.body.append(dlg);
    r("cancel").addEventListener("click", function () { dlg.close("cancel"); });
    // Validation via close() plutôt que par le formulaire natif, pour profiter de l'animation de fermeture
    dlg.querySelector("form").addEventListener("submit", function (e) { e.preventDefault(); dlg.close("ok"); });
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close("cancel"); });
    dlg.addEventListener("close", function () {
      var ok = dlg.returnValue === "ok", cb = done;
      done = null;
      if (!cb) return;
      if (opts.input) cb(ok ? dlg.querySelector("textarea").value.trim() : null);
      else cb(ok);
    });
  }
  function r(name) { return dlg.querySelector('[data-r="' + name + '"]'); }

  window.ask = function (o) {
    build();
    opts = o || {};
    if (dlg.open) dlg.close("cancel");
    dlg.querySelector("#ask-title").textContent = opts.title || "Confirmer ?";
    var msg = dlg.querySelector("#ask-msg");
    msg.textContent = opts.message || "";
    msg.hidden = !opts.message;
    var field = r("field"), area = dlg.querySelector("textarea");
    field.hidden = !opts.input;
    area.value = "";
    if (opts.input) {
      field.querySelector("label").textContent = opts.input.label || "";
      area.placeholder = opts.input.placeholder || "";
    }
    var ok = r("ok");
    ok.textContent = opts.confirm || "Confirmer";
    ok.className = opts.danger ? "danger-fill" : "";
    r("cancel").textContent = opts.cancel || "Annuler";
    dlg.returnValue = "";
    return new Promise(function (resolve) {
      done = resolve;
      dlg.showModal();
      // Action risquée : le focus va sur « Annuler » pour éviter une validation par réflexe
      (opts.input ? area : opts.danger ? r("cancel") : ok).focus();
    });
  };

  window.toast = function (text, kind) {
    if (!region) mountRegion();
    var t = document.createElement("div");
    t.className = "toast" + (kind === "err" ? " err" : "");
    t.textContent = text;
    region.append(t);
    setTimeout(function () {
      t.classList.add("out");
      setTimeout(function () { t.remove(); }, 220);
    }, kind === "err" ? 5000 : 2800);
  };
  function mountRegion() {
    region = document.createElement("div");
    region.className = "toasts";
    region.setAttribute("role", "status");
    region.setAttribute("aria-live", "polite");
    document.body.append(region);
  }
  // La zone doit exister avant le premier message pour être annoncée par les lecteurs d'écran
  document.addEventListener("DOMContentLoaded", function () { if (!region) mountRegion(); });

  // navigator.clipboard n'existe qu'en HTTPS (ou localhost) : repli sur execCommand sinon
  window.copyText = function (text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var t = document.createElement("textarea");
      t.value = text;
      t.setAttribute("readonly", "");
      t.style.cssText = "position:fixed;top:0;left:0;opacity:0";
      // Dans une fenêtre modale ouverte, le reste de la page est inerte : on y place le champ
      (document.querySelector("dialog[open]") || document.body).append(t);
      t.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { /* non pris en charge */ }
      t.remove();
      ok ? resolve() : reject(new Error("copy"));
    });
  };
})();
