/* Fenêtre QR code : génère, affiche, puis propose partage, copie et téléchargement.
   Utilisation : openQr(code, shortUrl). Nécessite icons.js et ui.js. */
(function () {
  var dlg, st = {};

  var HTML =
    '<div class="qr-body">' +
      '<div class="qr-head">' +
        '<h2>QR code</h2>' +
        '<button type="button" class="ghost icon-btn" data-act="close" aria-label="Fermer"><i data-i="x"></i></button>' +
      '</div>' +
      '<div class="qr-stage">' +
        '<div class="spinner" data-role="spin" role="status" aria-label="Génération du QR code"></div>' +
        '<img data-role="img" alt="QR code du lien" width="230" height="230" hidden>' +
        '<p data-role="fail" class="qr-fail" hidden>QR code indisponible</p>' +
      '</div>' +
      '<div class="qr-url" data-role="url"></div>' +
      '<div class="qr-actions">' +
        '<button type="button" data-act="share" data-blob hidden><i data-i="share"></i>Partager</button>' +
        '<button type="button" class="ghost" data-act="copy-img" data-blob hidden><i data-i="image"></i>Copier l\'image</button>' +
        '<button type="button" class="ghost" data-act="copy-link"><i data-i="copy"></i>Copier le lien</button>' +
        '<a class="btn" data-role="png" data-blob href="#"><i data-i="download"></i>PNG</a>' +
        '<a class="btn" data-role="svg" href="#"><i data-i="download"></i>SVG</a>' +
      '</div>' +
      '<div class="qr-social">' +
        '<span class="muted">Envoyer le lien par</span>' +
        '<a class="btn" data-net="whatsapp" target="_blank" rel="noopener"><i data-i="message"></i>WhatsApp</a>' +
        '<a class="btn" data-net="telegram" target="_blank" rel="noopener"><i data-i="message"></i>Telegram</a>' +
        '<a class="btn" data-net="facebook" target="_blank" rel="noopener"><i data-i="external"></i>Facebook</a>' +
        '<a class="btn" data-net="email"><i data-i="mail"></i>E-mail</a>' +
      '</div>' +
      '<p class="muted qr-msg" data-role="msg" role="status"></p>' +
    '</div>';

  function q(sel) { return dlg.querySelector(sel); }
  function role(name) { return q('[data-role="' + name + '"]'); }
  function msg(text) { role("msg").textContent = text || ""; }

  function flash(btn, name, label) {
    var old = btn.innerHTML;
    window.setLabel(btn, name, label);
    setTimeout(function () { btn.innerHTML = old; }, 1600);
  }

  function release() {
    if (st.objUrl) URL.revokeObjectURL(st.objUrl);
    st = {};
  }

  function build() {
    dlg = document.createElement("dialog");
    dlg.className = "qr-dlg";
    dlg.innerHTML = HTML;
    document.body.append(dlg);
    window.hydrateIcons(dlg);

    // Fermeture : clic sur le fond ou Échap
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener("close", release);

    // Le bouton Partager n'apparaît que si le navigateur sait partager ; idem pour la copie d'image
    if (navigator.share) q('[data-act="share"]').hidden = false;
    if (window.ClipboardItem && navigator.clipboard && navigator.clipboard.write) q('[data-act="copy-img"]').hidden = false;

    dlg.addEventListener("click", async function (e) {
      var btn = e.target.closest("[data-act]");
      if (!btn) return;
      var act = btn.getAttribute("data-act");
      msg("");

      if (act === "close") return dlg.close();

      if (act === "copy-link") {
        try { await window.copyText(st.shortUrl); flash(btn, "check", "Lien copié"); }
        catch (err) { msg("Copie impossible sur ce navigateur."); }
        return;
      }

      if (act === "copy-img") {
        try {
          await navigator.clipboard.write([new ClipboardItem({ "image/png": st.blob })]);
          flash(btn, "check", "Image copiée");
        } catch (err) { msg("Copie de l'image impossible sur ce navigateur."); }
        return;
      }

      if (act === "share") {
        var file = new File([st.blob], "qr-" + st.code + ".png", { type: "image/png" });
        var data = { title: "Mon lien court", text: st.shortUrl, url: st.shortUrl };
        if (navigator.canShare && navigator.canShare({ files: [file] })) data.files = [file];
        try { await navigator.share(data); }
        catch (err) { if (err && err.name !== "AbortError") msg("Partage impossible."); }
      }
    });
  }

  window.openQr = async function (code, shortUrl) {
    if (!dlg) build();
    release();
    st = { code: code, shortUrl: shortUrl };
    dlg.setAttribute("aria-label", "QR code");

    var enc = encodeURIComponent(shortUrl);
    role("url").textContent = shortUrl.replace(/^https?:\/\//, "");
    role("svg").href = "/api/qr/" + encodeURIComponent(code) + "?format=svg&download=1";
    q('[data-net="whatsapp"]').href = "https://wa.me/?text=" + enc;
    q('[data-net="telegram"]').href = "https://t.me/share/url?url=" + enc;
    q('[data-net="facebook"]').href = "https://www.facebook.com/sharer/sharer.php?u=" + enc;
    q('[data-net="email"]').href = "mailto:?subject=" + encodeURIComponent("Lien court") + "&body=" + enc;

    // État "génération en cours"
    role("img").hidden = true;
    role("spin").hidden = false;
    role("fail").hidden = true;
    msg("");
    dlg.querySelectorAll("[data-blob]").forEach(function (b) { b.setAttribute("aria-disabled", "true"); b.disabled = true; });
    if (!dlg.open) dlg.showModal();

    try {
      var res = await fetch("/api/qr/" + encodeURIComponent(code) + "?format=png");
      if (!res.ok) throw new Error("http " + res.status);
      var blob = await res.blob();
      if (st.code !== code) return; // fenêtre fermée ou autre lien ouvert entre-temps
      st.blob = blob;
      st.objUrl = URL.createObjectURL(blob);
      role("img").src = st.objUrl;
      role("img").hidden = false;
      role("spin").hidden = true;
      var png = role("png");
      png.href = st.objUrl;
      png.setAttribute("download", "qr-" + code + ".png");
      dlg.querySelectorAll("[data-blob]").forEach(function (b) { b.removeAttribute("aria-disabled"); b.disabled = false; });
    } catch (err) {
      role("spin").hidden = true;
      role("fail").hidden = false;
      msg("Impossible de générer le QR code. Réessaie dans un instant.");
    }
  };
})();
