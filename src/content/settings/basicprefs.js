var PAGE_STRINGS = [
  'basic',
  'advanced',
  'webPages',
  'indicateBlockedImages',
  'dontIndicateBlacklisted',
  'autoReload',
  'menu',
  'allowAddingNonTemporaryRulesInPBM'
];

$(function () {
  common.localize(PAGE_STRINGS);
});

Cu.import("resource://gre/modules/Services.jsm");


function updateDisplay() {
  var indicate = rpPrefBranch.getBoolPref('indicateBlockedObjects');
  $id('pref-indicateBlockedObjects').checked = indicate;
  $id('indicateBlockedImages-details').hidden = !indicate;

  $id('pref-dontIndicateBlacklistedObjects').checked =
      !rpPrefBranch.getBoolPref('indicateBlacklistedObjects');

  $id('pref-autoReload').checked =
      rpPrefBranch.getBoolPref('autoReload');

  $id('pref-privateBrowsingPermanentWhitelisting').checked =
      rpPrefBranch.getBoolPref('privateBrowsingPermanentWhitelisting');

//  if (rpPrefBranch.getBoolPref('defaultPolicy.allow')) {
//    var word = 'allow';
//  } else {
//    var word = 'block';
//  }
//  $id('defaultpolicyword').innerHTML = word;
}


function onload() {
  updateDisplay();

  elManager.addListener(
      $id('pref-indicateBlockedObjects'), 'change',
      function (event) {
        rpPrefBranch.setBoolPref('indicateBlockedObjects', event.target.checked);
        Services.prefs.savePrefFile(null);
        updateDisplay();
      });

  elManager.addListener(
      $id('pref-dontIndicateBlacklistedObjects'), 'change',
      function (event) {
        rpPrefBranch.setBoolPref('indicateBlacklistedObjects',
                                 !event.target.checked);
        Services.prefs.savePrefFile(null);
        updateDisplay();
      });

  elManager.addListener($id('pref-autoReload'), 'change', function(event) {
    rpPrefBranch.setBoolPref('autoReload', event.target.checked);
    Services.prefs.savePrefFile(null);
    updateDisplay();
  });

  elManager.addListener(
      $id('pref-privateBrowsingPermanentWhitelisting'), 'change',
      function (event) {
        rpPrefBranch.setBoolPref('privateBrowsingPermanentWhitelisting',
                                 event.target.checked);
        Services.prefs.savePrefFile(null);
        updateDisplay();
      });

  // call updateDisplay() every time a preference gets changed
  WinEnv.obMan.observePrefChanges(updateDisplay);
}
