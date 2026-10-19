// jsdom does not implement the native dialog methods provided by Electron Chromium.
if (typeof HTMLDialogElement !== "undefined") {
  HTMLDialogElement.prototype.showModal ??= function () {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close ??= function () {
    this.removeAttribute("open");
  };
}
