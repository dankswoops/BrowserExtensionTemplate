const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

document.getElementById('testButton').addEventListener('click', function() {
  browserAPI.tabs.query({active: true, currentWindow: true}, function(tabs) {
    browserAPI.tabs.sendMessage(tabs[0].id, {action: "showAlert"});
  });
});