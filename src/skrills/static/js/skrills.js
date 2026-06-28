// Client-side report download: decode the base64 payload embedded in the button
// and save it as a file. No server round-trip, so downloads work even when scans
// are never persisted (public mode).
function base64ToBlob(b64, mime) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes], { type: mime });
}

function downloadFromButton(btn) {
  const blob = base64ToBlob(btn.dataset.payload, btn.dataset.mime);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = btn.dataset.filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("[data-download]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      downloadFromButton(btn);
    });
  });
});
