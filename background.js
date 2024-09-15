const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

browserAPI.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "showAlert") {
    browserAPI.tabs.query({active: true, currentWindow: true}, function(tabs) {
      browserAPI.tabs.sendMessage(tabs[0].id, {action: "showAlert"});
    });
  }
});