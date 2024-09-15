const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

browserAPI.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "showAlert") {
    alert("It's Working from Content Script!");
  }
});