// System00-Security Ctf Blueprints
(function() {
    var _old_alert = window.alert;
    window.alert = function() {
        document.body.innerHTML += "Javascript Executed";
        _old_alert.apply(window,arguments);
        document.body.innerHTML += "Javascript Execution Done";
    };
})();
