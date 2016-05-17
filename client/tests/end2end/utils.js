var fs = require('fs');
var path = require('path');

exports.waitUntilReady = function (elm, timeout) {
  var t = timeout === undefined ? 1000 : timeout;
  browser.wait(function () {
    return elm.isPresent();
  }, t);
  browser.wait(function () {
    return elm.isDisplayed();
  }, t);
};

browser.getCapabilities().then(function(capabilities) {
  exports.testFileUpload = function() {
    var browserName = capabilities.get('browserName').toLowerCase();
    return (['chrome', 'firefox', 'internet explorer', 'edge'].indexOf(browserName) !== -1);
  };

  exports.testFileDownload = function() {
    // The only browser that does not ask for user interaction is chrome
    var browserName = capabilities.get('browserName').toLowerCase();
    var platform = capabilities.get('platform').toLowerCase();
    return ((['firefox', 'chrome'].indexOf(browserName) !== -1) && platform === 'linux');
  };

  exports.verifyFileDownload = function() {
    if (!browser.params.verifyFileDownload) {
      return false;
    }
  };
});

exports.waitForUrl = function (url) {
  browser.wait(function() {
    return browser.getCurrentUrl().then(function(current_url) {
      return (current_url.indexOf(url) !== -1);
    });
  });
};

exports.waitForFile = function (filename, timeout) {    
  var t = timeout === undefined ? 1000 : timeout;    
  var fp = path.resolve(browser.params.tmpDir, filename);   
  browser.wait(function() {    
    try {   
      var buf = fs.readFileSync(fp);   
      if (buf.length > 1000) {    
        return true;   
      }   
    } catch(err) {   
      return false;   
    }    
  }, t);    
};

exports.emulateUserRefresh = function () {
  browser.actions().sendKeys(protractor.Key.CONTROL, 'r', protractor.Key.NULL).perform();
  browser.waitForAngular();
}
