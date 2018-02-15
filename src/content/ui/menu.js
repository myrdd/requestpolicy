/*
 * ***** BEGIN LICENSE BLOCK *****
 *
 * RequestPolicy - A Firefox extension for control over cross-site requests.
 * Copyright (c) 2008 Justin Samuel
 * Copyright (c) 2014 Martin Kimmerle
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * ***** END LICENSE BLOCK *****
 */

import {Level as EnvLevel} from "lib/environment";
import {Log} from "models/log";
import * as DomainUtil from "lib/utils/domain-utils";
import {Ruleset} from "lib/ruleset";
import {
  GUIOrigin, GUIDestination, GUILocation, GUILocationProperties,
} from "lib/classes/gui-location";
import * as DOMUtils from "lib/utils/dom-utils";
import * as WindowUtils from "lib/utils/window-utils";
import {C} from "data/constants";
import {Requests} from "models/requests";
import {rp} from "app/app.background";

const log = Log.instance;

export function loadMenuIntoWindow(window) {
  let {document, rpcontinued} = window;

  // ===========================================================================

  let gBrowser = WindowUtils.getTabBrowser(window);

  let initialized = false;

  // TODO: Create a "List" class which also contains functions like
  //       _populateList() and emptyList().
  const lists = {
    otherOrigins: null,
    blockedDestinations: null,
    mixedDestinations: null,
    allowedDestinations: null,
    removeRules: null,
    addRules: null,
  };

  let self = {
    addedMenuItems: [],

    _originItem: null,
    _originDomainnameItem: null,
    _isUncontrollableOrigin: null,
    _originNumRequestsItem: null,

    _isCurrentlySelectedDestBlocked: null,
    _isCurrentlySelectedDestAllowed: null,

    _ruleChangeQueues: {},
  };

  /**
   * Return a DOM element by its id. First search in the document included
   * in the frame, and if not found search in the main document.
   *
   * @param {string} id the DOM element's id
   * @return {Element} the DOM element or null if not found
   */
  let $id = function(id) {
    let element = null;
    let popupframe = window.top.document.getElementById("rpc-popup-frame");
    if (popupframe && popupframe.contentDocument) {
      element = popupframe.contentDocument.getElementById(id);
    }
    if (!element) {
      element = window.top.document.getElementById(id);
    }
    return element;
  };

  self.init = function() {
    if (initialized === false) {
      initialized = true;

      rpcontinued.overlay.OverlayEnvironment.addShutdownFunction(
          EnvLevel.INTERFACE,
          function() {
          // empty _all_ lists
            for (let listName in lists) {
              emptyList(lists[listName]);
            }
          }
      );
    }
  };

  // ---------------------------------------------------------------------------
  // utilities
  // ---------------------------------------------------------------------------

  /**
   * Show a dialog with "OK" and "Cancel" buttons, as well as with a
   * checkbox labeled "always ask?".
   *
   * @param {string} dialogMessage
   * @param {string} alwaysAskPrefName
   * @param {Object=} params
   * @return {boolean} If the question has been confirmed or not.
   */
  function confirm(dialogMessage, alwaysAskPrefName, params={}) {
    let shouldAsk = rp.storage.get(alwaysAskPrefName);
    if (shouldAsk === false) {
      // never ask
      return true;
    }

    let dialogTitle = params.dialogTitle || "RequestPolicy";
    let checkboxObj = {value: shouldAsk};
    let checkboxText = browser.i18n.getMessage("alwaysAsk");

    if (typeof params.onBeforeDialog === "function") {
      params.onBeforeDialog.call();
    }

    let confirmed = Services.prompt.confirmCheck(
        window, dialogTitle,
        dialogMessage, checkboxText, checkboxObj
    );

    if (confirmed) {
      // "OK" has been pressed
      rp.storage.set(alwaysAskPrefName, checkboxObj.value);
      return true;
    }
    // "Cancel" has been pressed
    return false;
  }

  /**
   * Remove all children from a list, and remove all event listeners.
   *
   * @param {Element} aList The list that should be emptied.
   */
  function emptyList(aList) {
    if (!aList) {
      return;
    }

    // remove all event listeners
    {
      let elements = aList.getElementsByClassName("listen-click");
      for (let el of elements) {
        el.removeEventListener("click", self.itemSelected, false);
      }
    }

    // remove the children
    DOMUtils.removeChildren(aList);
  }

  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------

  self.prepareMenu = function() {
    try {
      self._originItem = $id("rpc-origin");
      self._originDomainnameItem = $id("rpc-origin-domainname");
      self._originNumRequestsItem = $id("rpc-origin-num-requests");

      lists.otherOrigins = $id("rpc-other-origins-list");
      lists.blockedDestinations = $id("rpc-blocked-destinations-list");
      lists.mixedDestinations = $id("rpc-mixed-destinations-list");
      lists.allowedDestinations = $id("rpc-allowed-destinations-list");
      lists.addRules = $id("rpc-rules-add");
      lists.removeRules = $id("rpc-rules-remove");

      const disabled = rp.storage.alias.isBlockingDisabled();
      $id("rpc-link-enable-blocking").hidden = !disabled;
      $id("rpc-link-disable-blocking").hidden = disabled;

      let tempPermLink = $id("rpc-revoke-temporary-permissions");
      if (rp.policy.temporaryRulesExist()) {
        tempPermLink.className = "rpc-revoke-temporary-permissions-enable";
      } else {
        tempPermLink.className = "rpc-revoke-temporary-permissions-disable";
      }

      self._currentUri = rpcontinued.overlay.getTopLevelDocumentUri();

      try {
        self._currentBaseDomain = DomainUtil.getBaseDomain(self._currentUri);
        if (self._currentBaseDomain === null) {
          log.info(`${"Unable to prepare menu because " +
              "the current uri has no host: "}${self._currentUri}`);
          self._populateMenuForUncontrollableOrigin();
          return;
        }
      } catch (e) {
        log.info(`${"Unable to prepare menu because " +
            "base domain can't be determined: "}${self._currentUri}`);
        self._populateMenuForUncontrollableOrigin();
        return;
      }

      self._currentIdentifier = rpcontinued.overlay.
          getTopLevelDocumentUriIdentifier();

      // log.info("self._currentUri: " + self._currentUri);
      self._currentUriObj = DomainUtil.getUriObject(self._currentUri);

      self._isChromeUri = self._currentUriObj.scheme === "chrome";
      // self._currentUriIsHttps = self._currentUriObj.scheme === "https";

      log.info(`self._currentUri: ${self._currentUri}`);

      if (self._isChromeUri) {
        self._populateMenuForUncontrollableOrigin();
        return;
      }

      // The fact that getAllRequestsInBrowser uses currentURI.spec directly
      // from the browser is important because getTopLevelDocumentUri will
      // not return the real URI if there is an applicable
      // top-level document translation rule (these are used sometimes
      // for extension compatibility). For example, this is essential to the
      // menu showing relevant info when using the Update Scanner extension.
      self._allRequestsOnDocument = Requests.
          getAllRequestsInBrowser(gBrowser.selectedBrowser);
      self._allRequestsOnDocument.print("_allRequestsOnDocument");

      self._setPrivateBrowsingStyles();

      self._populateOrigin();
      self._populateOtherOrigins();
      self._activateOriginItem(self._originItem);
    } catch (e) {
      console.error("[Fatal] Unable to prepare menu! Details:");
      console.dir(e);
      // eslint-disable-next-line no-throw-literal
      throw e;
    }
  };

  self.close = function() {
    $id("rpc-popup").hidePopup();
  };

  self._populateMenuForUncontrollableOrigin = function() {
    self._originDomainnameItem.textContent =
        browser.i18n.getMessage("noOrigin");
    self._isUncontrollableOrigin = true;
    self._originNumRequestsItem.textContent = "";
    self._originItem.removeAttribute("default-policy");
    self._originItem.removeAttribute("requests-blocked");

    [
      lists.otherOrigins,
      lists.blockedDestinations,
      lists.mixedDestinations,
      lists.allowedDestinations,
      lists.removeRules,
      lists.addRules,
    ].forEach(emptyList);

    $id("rpc-other-origins").hidden = true;
    $id("rpc-blocked-destinations").hidden = true;
    $id("rpc-mixed-destinations").hidden = true;
    $id("rpc-allowed-destinations").hidden = true;
    // TODO: show some message about why the menu is empty.
  };

  self._populateList = function(list, values) {
    emptyList(list);

    // check whether there are objects of GUILocation or just strings
    let guiLocations = values[0] && values[0] instanceof GUILocation;

    if (true === guiLocations) {
      // get prefs
      let sorting = rp.storage.get("menu.sorting");
      let showNumRequests = rp.storage.get("menu.info.showNumRequests");

      if (sorting === "numRequests") {
        values.sort(GUILocation.sortByNumRequestsCompareFunction);
      } else if (sorting === "destName") {
        values.sort(GUILocation.compareFunction);
      }

      for (let i in values) {
        let guiLocation = values[i];
        let props = guiLocation.properties;

        let num;
        if (true === showNumRequests) {
          num = props.numRequests;
          if (props.numAllowedRequests > 0 && props.numBlockedRequests > 0) {
            num += ` (${props.numBlockedRequests
            }+${props.numAllowedRequests})`;
          }
        }
        let newitem = self._addListItem(list, "rpc-od-item", guiLocation, num);

        newitem.setAttribute(
            "default-policy",
            props.numDefaultPolicyRequests > 0 ? "true" : "false"
        );
        newitem.setAttribute(
            "requests-blocked",
            props.numBlockedRequests > 0 ? "true" : "false"
        );
      }
    } else {
      values.sort();
      for (let i in values) {
        self._addListItem(list, "rpc-od-item", values[i]);
      }
    }
  };

  self._populateOrigin = function() {
    self._originDomainnameItem.textContent = self._currentBaseDomain;
    self._isUncontrollableOrigin = false;

    let showNumRequests = rp.storage.get("menu.info.showNumRequests");

    let props = self._getOriginGUILocationProperties();

    let numRequests = "";
    if (true === showNumRequests) {
      if (props.numAllowedRequests > 0 && props.numBlockedRequests > 0) {
        numRequests = `${props.numRequests}\u00a0(` +
            `${props.numBlockedRequests}+${props.numAllowedRequests})`;
      } else {
        numRequests = props.numRequests;
      }
    }
    self._originNumRequestsItem.textContent = numRequests;

    self._originItem.setAttribute(
        "default-policy",
        props.numDefaultPolicyRequests > 0 ? "true" : "false"
    );
    self._originItem.setAttribute(
        "requests-blocked",
        props.numBlockedRequests > 0 ? "true" : "false"
    );
  };

  self._populateOtherOrigins = function() {
    let guiOrigins = self._getOtherOriginsAsGUILocations();
    self._populateList(lists.otherOrigins, guiOrigins);
    $id("rpc-other-origins").hidden = guiOrigins.length === 0;
  };

  self._populateDestinations = function(originIdentifier) {
    let destsWithBlockedRequests = self._getBlockedDestinationsAsGUILocations();
    let destsWithAllowedRequests = self._getAllowedDestinationsAsGUILocations();

    let destsWithSolelyBlockedRequests = [];
    let destsMixed = [];
    let destsWithSolelyAllowedRequests = [];

    // Set operations would be nice. These are small arrays, so keep it simple.
    for (let i = 0; i < destsWithBlockedRequests.length; i++) {
      let blockedGUIDest = destsWithBlockedRequests[i];

      if (false === GUILocation.existsInArray(
          blockedGUIDest,
          destsWithAllowedRequests
      )) {
        destsWithSolelyBlockedRequests.push(blockedGUIDest);
      } else {
        destsMixed.push(blockedGUIDest);
      }
    }
    for (let i = 0; i < destsWithAllowedRequests.length; i++) {
      let allowedGUIDest = destsWithAllowedRequests[i];

      let indexRawBlocked = GUIDestination.
          indexOfDestInArray(allowedGUIDest, destsWithBlockedRequests);
      let destsMixedIndex = GUIDestination.
          indexOfDestInArray(allowedGUIDest, destsMixed);

      if (indexRawBlocked === -1) {
        destsWithSolelyAllowedRequests.push(allowedGUIDest);
      } else {
        if (destsMixedIndex !== -1) {
          log.info(`Merging dest: <${allowedGUIDest}>`);
          destsMixed[destsMixedIndex] = GUIDestination.merge(
              allowedGUIDest, destsMixed[destsMixedIndex]
          );
        } else {
          // If the allowedGUIDest is in destsWithBlockedRequests and
          // destsWithAllowedRequests, but not in destsMixed.
          // This should never happen, the destsMixed destination should have
          // been added in the destsWithBlockedRequests-loop.
          log.warn(`${"mixed dest was" +
              " not added to `destsMixed` list: <"}${allowedGUIDest}>`);
          destsMixed.push(allowedGUIDest);
        }
      }
    }

    self._populateList(
        lists.blockedDestinations,
        destsWithSolelyBlockedRequests
    );
    $id("rpc-blocked-destinations").hidden =
        destsWithSolelyBlockedRequests.length === 0;

    self._populateList(lists.mixedDestinations, destsMixed);
    $id("rpc-mixed-destinations").hidden = destsMixed.length === 0;

    self._populateList(
        lists.allowedDestinations,
        destsWithSolelyAllowedRequests
    );
    $id("rpc-allowed-destinations").hidden =
        destsWithSolelyAllowedRequests.length === 0;
  };

  // eslint-disable-next-line complexity
  self._populateDetails = function() {
    let origin = self._currentlySelectedOrigin;
    let dest = self._currentlySelectedDest;

    emptyList(lists.removeRules);
    emptyList(lists.addRules);

    let ruleData = {
      "o": {
        "h": self._addWildcard(origin),
      },
    };

    let mayPermRulesBeAdded = WindowUtils.mayPermanentRulesBeAdded(
        window, rp.storage
    );

    // Note: in PBR we'll need to still use the old string for the temporary
    // rule. We won't be able to use just "allow temporarily".

    if (!self._currentlySelectedDest) {
      if (rp.storage.alias.isDefaultAllow()) {
        if (mayPermRulesBeAdded === true) {
          self._addMenuItemDenyOrigin(lists.addRules, ruleData);
        }
        self._addMenuItemTempDenyOrigin(lists.addRules, ruleData);
      } else {
        if (mayPermRulesBeAdded === true) {
          self._addMenuItemAllowOrigin(lists.addRules, ruleData);
        }
        self._addMenuItemTempAllowOrigin(lists.addRules, ruleData);
      }
    }

    if (dest) {
      ruleData.d = {
        "h": self._addWildcard(dest),
      };
      const destOnlyRuleData = {
        "d": {
          "h": self._addWildcard(dest),
        },
      };
      // if (rp.storage.alias.isDefaultAllow()) {
      if (self._isCurrentlySelectedDestAllowed ||
          !rp.policy.ruleExists(C.RULE_ACTION_DENY, ruleData) &&
              !rp.policy.ruleExists(C.RULE_ACTION_DENY, destOnlyRuleData)) {
        // show "Block requests" if the destination was allowed
        // OR if there's no blocking rule (i.e. the request was blocked
        // "by default") -- this enables support for blacklisting.
        if (!rp.policy.ruleExists(C.RULE_ACTION_ALLOW, ruleData) &&
            !rp.policy.ruleExists(C.RULE_ACTION_DENY, ruleData)) {
          if (mayPermRulesBeAdded === true) {
            self._addMenuItemDenyOriginToDest(lists.addRules, ruleData);
          }
          self._addMenuItemTempDenyOriginToDest(lists.addRules, ruleData);
        }

        if (!rp.policy.ruleExists(C.RULE_ACTION_ALLOW, destOnlyRuleData) &&
            !rp.policy.ruleExists(C.RULE_ACTION_DENY, destOnlyRuleData)) {
          if (mayPermRulesBeAdded === true) {
            self._addMenuItemDenyDest(lists.addRules, destOnlyRuleData);
          }
          self._addMenuItemTempDenyDest(lists.addRules, destOnlyRuleData);
        }
      }
      if (self._isCurrentlySelectedDestBlocked ||
          !rp.policy.ruleExists(C.RULE_ACTION_ALLOW, ruleData) &&
              !rp.policy.ruleExists(
                  C.RULE_ACTION_ALLOW,
                  destOnlyRuleData
              )) {
        // show "Allow requests" if the destination was blocked
        // OR if there's no allow-rule (i.e. the request was allowed
        // "by default") -- this enables support for whitelisting.
        if (!rp.policy.ruleExists(C.RULE_ACTION_ALLOW, ruleData) &&
            !rp.policy.ruleExists(C.RULE_ACTION_DENY, ruleData)) {
          if (mayPermRulesBeAdded === true) {
            self._addMenuItemAllowOriginToDest(lists.addRules, ruleData);
          }
          self._addMenuItemTempAllowOriginToDest(lists.addRules, ruleData);
        }

        if (!rp.policy.ruleExists(C.RULE_ACTION_ALLOW, destOnlyRuleData) &&
            !rp.policy.ruleExists(C.RULE_ACTION_DENY, destOnlyRuleData)) {
          if (mayPermRulesBeAdded === true) {
            self._addMenuItemAllowDest(lists.addRules, destOnlyRuleData);
          }
          self._addMenuItemTempAllowDest(lists.addRules, destOnlyRuleData);
        }
      }
    }

    if (self._currentlySelectedDest) {
      if (!rp.storage.alias.isDefaultAllow() &&
          !rp.storage.alias.isDefaultAllowSameDomain()) {
        self._populateDetailsAddSubdomainAllowRules(lists.addRules);
      }
    }

    self._populateDetailsRemoveAllowRules(lists.removeRules);
    self._populateDetailsRemoveDenyRules(lists.removeRules);
  };

  self._addListItem = function(list, cssClass, value, numRequests) {
    const box = document.createElement("div");
    box.setAttribute("class", `${cssClass} listen-click`);
    box.addEventListener("click", self.itemSelected, false);
    list.insertBefore(box, null);

    const destLabel = document.createElement("span");
    destLabel.textContent = value;
    destLabel.setAttribute("class", "domainname");
    box.insertBefore(destLabel, null);

    if (numRequests) {
      const numReqLabel = document.createElement("span");
      numReqLabel.textContent = numRequests;
      numReqLabel.setAttribute("class", "numRequests");
      box.insertBefore(numReqLabel, null);
    }

    return box;
  };

  self._disableIfNoChildren = function(el) {
    // TODO: this isn't working.
    // eslint-disable-next-line no-param-reassign
    el.hidden = el.firstChild ? false : true;
  };

  self._setPrivateBrowsingStyles = function() {
    let mayPermRulesBeAdded = WindowUtils.mayPermanentRulesBeAdded(
        window, rp.storage
    );
    let val = mayPermRulesBeAdded === true ? "" : "privatebrowsing";
    $id("rpc-details").setAttribute("class", val);
  };

  self._resetSelectedOrigin = function() {
    self._originItem.setAttribute("selected-origin", "false");
    for (let i = 0; i < lists.otherOrigins.childNodes.length; i++) {
      const child = lists.otherOrigins.childNodes[i];
      child.setAttribute("selected-origin", "false");
    }
  };

  self._resetSelectedDest = function() {
    for (let i = 0; i < lists.blockedDestinations.childNodes.length; i++) {
      let child = lists.blockedDestinations.childNodes[i];
      child.setAttribute("selected-dest", "false");
    }
    for (let i = 0; i < lists.mixedDestinations.childNodes.length; i++) {
      let child = lists.mixedDestinations.childNodes[i];
      child.setAttribute("selected-dest", "false");
    }
    for (let i = 0; i < lists.allowedDestinations.childNodes.length; i++) {
      let child = lists.allowedDestinations.childNodes[i];
      child.setAttribute("selected-dest", "false");
    }
  };

  self._activateOriginItem = function(item) {
    if (item.id === "rpc-origin") {
      // it's _the_ origin
      if (self._isUncontrollableOrigin) {
        return;
      }
      self._currentlySelectedOrigin = self._originDomainnameItem.textContent;
    } else if (item.parentNode.id === "rpc-other-origins-list") {
      // it's an otherOrigin
      self._currentlySelectedOrigin =
          item.getElementsByClassName("domainname")[0].textContent;
    }
    self._currentlySelectedDest = null;
    // TODO: if the document's origin (rather than an other origin) is being
    // activated, then regenerate the other origins list, as well.
    self._resetSelectedOrigin();
    item.setAttribute("selected-origin", "true");
    self._populateDestinations();
    self._resetSelectedDest();
    self._populateDetails();
  };

  self._activateDestinationItem = function(item) {
    self._currentlySelectedDest =
        item.getElementsByClassName("domainname")[0].textContent;

    if (item.parentNode.id === "rpc-blocked-destinations-list") {
      self._isCurrentlySelectedDestBlocked = true;
      self._isCurrentlySelectedDestAllowed = false;
    } else if (item.parentNode.id === "rpc-allowed-destinations-list") {
      self._isCurrentlySelectedDestBlocked = false;
      self._isCurrentlySelectedDestAllowed = true;
    } else {
      self._isCurrentlySelectedDestBlocked = true;
      self._isCurrentlySelectedDestAllowed = true;
    }

    self._resetSelectedDest();
    item.setAttribute("selected-dest", "true");
    self._populateDetails();
  };

  function openSiteInfoTab(domain) {
    let url = `https://www.mywot.com/en/scorecard/${domain}`;
    window.openUILinkIn(url, "tab", {
      relatedToCurrent: true,
      inBackground: true,
    });
  }

  function maybeOpenSiteInfoTab(item) {
    let domain = null;

    if (item.value) {
      domain = item.value;
    } else {
      let domainLabel = item.querySelector(".domainname");

      if (domainLabel !== null) {
        domain = domainLabel.textContent;
      }
    }

    if (domain === null) {
      console.error("Failed to determine the domain under the mouse button " +
          "after the middle-click.");
      return;
    }

    let dialogMessage = browser.i18n.getMessage("siteInfoConfirm",
        [domain, "https://www.mywot.com"]);
    let alwaysAskPrefName = "confirmSiteInfo";
    let confirmed = confirm(dialogMessage, alwaysAskPrefName, {
      // close the menu if the dialog needs to be shown
      onBeforeDialog: self.close,
    });
    if (confirmed) {
      openSiteInfoTab(domain);
    }
  }

  self.itemSelected = function(event) {
    // We retrieve the element on which the listener was added to always
    // get the div (and not one span or textnode children)
    let item = event.currentTarget;
    // TODO: rather than compare IDs, this should probably compare against
    // the elements we already have stored in variables. That is, assuming
    // equality comparisons work that way here.
    if (item.id === "rpc-origin" ||
        item.parentNode.id === "rpc-other-origins-list") {
      if (event.button === 1) {
        maybeOpenSiteInfoTab(item);
      } else {
        self._activateOriginItem(item);
      }
    } else if (item.parentNode.id === "rpc-blocked-destinations-list" ||
               item.parentNode.id === "rpc-mixed-destinations-list" ||
               item.parentNode.id === "rpc-allowed-destinations-list") {
      if (event.button === 1) {
        maybeOpenSiteInfoTab(item);
      } else {
        self._activateDestinationItem(item);
      }
    } else if (item.parentNode.id === "rpc-rules-remove" ||
               item.parentNode.id === "rpc-rules-add") {
      self._processRuleSelection(item);
    } else {
      console.error("Unable to figure out which item type was selected.");
    }
  };

  self._processRuleSelection = function(item) {
    const ruleData = item.requestpolicyRuleData;
    const ruleAction = item.requestpolicyRuleAction;

    let undo;
    if (item.getAttribute("selected-rule") === "true") {
      item.setAttribute("selected-rule", "false");
      undo = true;
    } else {
      item.setAttribute("selected-rule", "true");
      undo = false;
    }

    if (!ruleData) {
      console.error("ruleData is empty in menu._processRuleSelection()");
      return;
    }
    if (!ruleAction) {
      console.error("ruleAction is empty in menu._processRuleSelection()");
      return;
    }

    const canonicalRule = Ruleset.rawRuleToCanonicalString(ruleData);
    log.log(`ruleData: ${canonicalRule}`);
    log.log(`ruleAction: ${ruleAction}`);
    log.log(`undo: ${undo}`);

    // TODO: does all of this get replaced with a generic rule processor that
    // only cares whether it's an allow/deny and temporary and drops the
    // ruleData argument straight into the ruleset?
    /* eslint-disable no-unused-vars */
    let origin;
    let dest;
    /* eslint-enable no-unused-vars */
    if (ruleData.o && ruleData.o.h) {
      origin = ruleData.o.h;
    }
    if (ruleData.d && ruleData.d.h) {
      dest = ruleData.d.h;
    }

    if (!self._ruleChangeQueues[ruleAction]) {
      self._ruleChangeQueues[ruleAction] = {};
    }

    if (undo) {
      delete self._ruleChangeQueues[ruleAction][canonicalRule];
    } else {
      self._ruleChangeQueues[ruleAction][canonicalRule] = ruleData;
    }
  };

  self.processQueuedRuleChanges = function() {
    let rulesChanged = false;
    for (let ruleAction in self._ruleChangeQueues) {
      for (let canonicalRule in self._ruleChangeQueues[ruleAction]) {
        let ruleData = self._ruleChangeQueues[ruleAction][canonicalRule];
        self._processRuleChange(ruleAction, ruleData);
        rulesChanged = true;
      }
    }

    self._ruleChangeQueues = {};
    return rulesChanged;
  };

  self._processRuleChange = function(ruleAction, ruleData) {
    switch (ruleAction) {
      case "allow":
        rp.policy.addAllowRule(ruleData);
        break;
      case "allow-temp":
        rp.policy.addTemporaryAllowRule(ruleData);
        break;
      case "stop-allow":
        rp.policy.removeAllowRule(ruleData);
        break;
      case "deny":
        rp.policy.addDenyRule(ruleData);
        break;
      case "deny-temp":
        rp.policy.addTemporaryDenyRule(ruleData);
        break;
      case "stop-deny":
        rp.policy.removeDenyRule(ruleData);
        break;
      default:
        // eslint-disable-next-line no-throw-literal
        throw `action not implemented: ${ruleAction}`;
    }
  };

  // Note by @jsamuel:
  // „It's been too long since I looked at some of the new code.
  //  I think I may have assumed that I'd get rid of the different strictness
  //  levels and just use what is currently called LEVEL_SOP. If using anything
  //  else there will be errors from within getDeniedRequests().“

  self._getBlockedDestinationsAsGUILocations = function() {
    const reqSet = Requests.getDeniedRequests(
        self._currentlySelectedOrigin, self._allRequestsOnDocument
    );
    const requests = reqSet.getAllMergedOrigins();

    const result = [];
    for (let destBase in requests) {
      const properties = new GUILocationProperties();
      properties.accumulate(requests[destBase], C.RULE_ACTION_DENY);
      result.push(new GUIDestination(destBase, properties));
    }
    return result;
  };

  self._getAllowedDestinationsAsGUILocations = function() {
    const reqSet = Requests.getAllowedRequests(
        self._currentlySelectedOrigin, self._allRequestsOnDocument
    );
    const requests = reqSet.getAllMergedOrigins();

    const result = [];
    for (let destBase in requests) {
      // For everybody except users with default deny who are not allowing all
      // requests to the same domain:
      // Ignore the selected origin's domain when listing destinations.
      if (
        rp.storage.alias.isDefaultAllow() ||
          rp.storage.alias.isDefaultAllowSameDomain()
      ) {
        if (destBase === self._currentlySelectedOrigin) {
          continue;
        }
      }

      const properties = new GUILocationProperties();
      properties.accumulate(requests[destBase], C.RULE_ACTION_ALLOW);
      result.push(new GUIDestination(destBase, properties));
    }
    return result;
  };

  /**
   * TODO: optimize this for performance (_getOriginGUILocationProperties and
   * _getOtherOriginsAsGUILocations could be merged.)
   *
   * @return {GUILocationProperties}
   *         the properties of the "main" origin (the one in the location bar).
   */
  self._getOriginGUILocationProperties = function() {
    const allRequests = self._allRequestsOnDocument.getAll();

    const properties = new GUILocationProperties();

    for (let originUri in allRequests) {
      const originBase = DomainUtil.getBaseDomain(originUri);
      if (originBase !== self._currentBaseDomain) {
        continue;
      }

      for (let destBase in allRequests[originUri]) {
        properties.accumulate(allRequests[originUri][destBase]);
      }
    }
    return properties;
  };

  self._getOtherOriginsAsGUILocations = function() {
    const allRequests = self._allRequestsOnDocument.getAll();

    const allowSameDomain = rp.storage.alias.isDefaultAllow() ||
        rp.storage.alias.isDefaultAllowSameDomain();

    const guiOrigins = [];
    for (let originUri in allRequests) {
      const originBase = DomainUtil.getBaseDomain(originUri);
      if (originBase === self._currentBaseDomain) {
        continue;
      }

      // TODO: we should prevent chrome://browser/ URLs from getting anywhere
      // near here in the first place.
      // Is this an issue anymore? This may have been slipping through due to
      // a bug that has since been fixed. Disabling for now.
      // if (originBase === 'browser') {
      //   continue;
      // }

      const guiOriginsIndex = GUIOrigin.indexOfOriginInArray(
          originBase,
          guiOrigins
      );
      let properties;
      if (guiOriginsIndex === -1) {
        properties = new GUILocationProperties();
      } else {
        properties = guiOrigins[guiOriginsIndex].properties;
      }
      let addThisOriginBase = false;

      for (let destBase in allRequests[originUri]) {
        // Search for a destBase which wouldn't be allowed by the default
        // policy.
        // TODO: some users might want to know those "other origins" as well.
        //       this should be made possible.

        // For everybody except users with default deny who are not allowing all
        // guiOrigins to the same domain:
        // Only list other origins where there is a destination from that origin
        // that is at a different domain, not just a different subdomain.
        if (allowSameDomain && destBase === originBase) {
          continue;
        }
        addThisOriginBase = true;
        properties.accumulate(allRequests[originUri][destBase]);
      }

      if (addThisOriginBase && guiOriginsIndex === -1) {
        guiOrigins.push(new GUIOrigin(originBase, properties));
      }
    }
    return guiOrigins;
  };

  self._isIPAddressOrSingleName = function(hostname) {
    return DomainUtil.isIPAddress(hostname) ||
        hostname.indexOf(".") === -1;
  };

  self._addWildcard = function(hostname) {
    if (self._isIPAddressOrSingleName(hostname)) {
      return hostname;
    } else {
      return `*.${hostname}`;
    }
  };

  // TODO: the 12 _addMenuItem* functions below hopefully can be refactored.

  // Stop allowing

  self._addMenuItemStopAllowingOrigin = function(
      list, ruleData,
      subscriptionOverride
  ) {
    const originHost = ruleData.o.h;
    const ruleAction = subscriptionOverride ? "deny" : "stop-allow";
    return self._addMenuItemHelper(
        list, ruleData, "stopAllowingOrigin",
        [originHost], ruleAction, "rpc-stop-rule rpc-stop-allow"
    );
  };

  self._addMenuItemStopAllowingDest = function(
      list, ruleData,
      subscriptionOverride
  ) {
    const destHost = ruleData.d.h;
    const ruleAction = subscriptionOverride ? "deny" : "stop-allow";
    return self._addMenuItemHelper(
        list, ruleData, "stopAllowingDestination",
        [destHost], ruleAction, "rpc-stop-rule rpc-stop-allow"
    );
  };

  self._addMenuItemStopAllowingOriginToDest = function(
      list, ruleData,
      subscriptionOverride
  ) {
    const originHost = ruleData.o.h;
    const destHost = ruleData.d.h;
    const ruleAction = subscriptionOverride ? "deny" : "stop-allow";
    return self._addMenuItemHelper(
        list, ruleData,
        "stopAllowingOriginToDestination", [originHost, destHost], ruleAction,
        "rpc-stop-rule rpc-stop-allow"
    );
  };

  // Allow

  self._addMenuItemAllowOrigin = function(list, ruleData) {
    const originHost = ruleData.o.h;
    return self._addMenuItemHelper(
        list, ruleData, "allowOrigin",
        [originHost], "allow", "rpc-start-rule rpc-allow"
    );
  };

  self._addMenuItemAllowDest = function(list, ruleData) {
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData, "allowDestination",
        [destHost], "allow", "rpc-start-rule rpc-allow"
    );
  };

  self._addMenuItemAllowOriginToDest = function(list, ruleData) {
    const originHost = ruleData.o.h;
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData, "allowOriginToDestination",
        [originHost, destHost], "allow", "rpc-start-rule rpc-allow"
    );
  };

  // Allow temp

  self._addMenuItemTempAllowOrigin = function(list, ruleData) {
    const originHost = ruleData.o.h;
    return self._addMenuItemHelper(
        list, ruleData, "allowOriginTemporarily",
        [originHost], "allow-temp", "rpc-start-rule rpc-allow rpc-temporary"
    );
  };

  self._addMenuItemTempAllowDest = function(list, ruleData) {
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData,
        "allowDestinationTemporarily", [destHost], "allow-temp",
        "rpc-start-rule rpc-allow rpc-temporary"
    );
  };

  self._addMenuItemTempAllowOriginToDest = function(list, ruleData) {
    const originHost = ruleData.o.h;
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData,
        "allowOriginToDestinationTemporarily", [originHost, destHost],
        "allow-temp", "rpc-start-rule rpc-allow rpc-temporary"
    );
  };

  // Stop denying

  self._addMenuItemStopDenyingOrigin = function(
      list, ruleData,
      subscriptionOverride
  ) {
    const originHost = ruleData.o.h;
    const ruleAction = subscriptionOverride ? "allow" : "stop-deny";
    return self._addMenuItemHelper(
        list, ruleData, "stopDenyingOrigin",
        [originHost], ruleAction, "rpc-stop-rule rpc-stop-deny"
    );
  };

  self._addMenuItemStopDenyingDest = function(
      list, ruleData,
      subscriptionOverride
  ) {
    const destHost = ruleData.d.h;
    const ruleAction = subscriptionOverride ? "allow" : "stop-deny";
    return self._addMenuItemHelper(
        list, ruleData, "stopDenyingDestination",
        [destHost], ruleAction, "rpc-stop-rule rpc-stop-deny"
    );
  };

  self._addMenuItemStopDenyingOriginToDest = function(
      list, ruleData,
      subscriptionOverride
  ) {
    const originHost = ruleData.o.h;
    const destHost = ruleData.d.h;
    const ruleAction = subscriptionOverride ? "allow" : "stop-deny";
    return self._addMenuItemHelper(
        list, ruleData,
        "stopDenyingOriginToDestination", [originHost, destHost], ruleAction,
        "rpc-stop-rule rpc-stop-deny"
    );
  };

  // Deny

  self._addMenuItemDenyOrigin = function(list, ruleData) {
    const originHost = ruleData.o.h;
    return self._addMenuItemHelper(
        list, ruleData, "denyOrigin",
        [originHost], "deny", "rpc-start-rule rpc-deny"
    );
  };

  self._addMenuItemDenyDest = function(list, ruleData) {
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData, "denyDestination",
        [destHost], "deny", "rpc-start-rule rpc-deny"
    );
  };

  self._addMenuItemDenyOriginToDest = function(list, ruleData) {
    const originHost = ruleData.o.h;
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData, "denyOriginToDestination",
        [originHost, destHost], "deny", "rpc-start-rule rpc-deny"
    );
  };

  // Deny temp

  self._addMenuItemTempDenyOrigin = function(list, ruleData) {
    const originHost = ruleData.o.h;
    return self._addMenuItemHelper(
        list, ruleData, "denyOriginTemporarily",
        [originHost], "deny-temp", "rpc-start-rule rpc-deny rpc-temporary"
    );
  };

  self._addMenuItemTempDenyDest = function(list, ruleData) {
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData, "denyDestinationTemporarily",
        [destHost], "deny-temp", "rpc-start-rule rpc-deny rpc-temporary"
    );
  };

  self._addMenuItemTempDenyOriginToDest = function(list, ruleData) {
    const originHost = ruleData.o.h;
    const destHost = ruleData.d.h;
    return self._addMenuItemHelper(
        list, ruleData,
        "denyOriginToDestinationTemporarily", [originHost, destHost],
        "deny-temp", "rpc-start-rule rpc-deny rpc-temporary"
    );
  };

  self._addMenuItemHelper = function(list, ruleData, fmtStrName, fmtStrArgs,
      ruleAction, cssClass) {
    const label = browser.i18n.getMessage(fmtStrName, fmtStrArgs);
    const item = self._addListItem(list, "rpc-od-item", label);
    item.requestpolicyRuleData = ruleData;
    item.requestpolicyRuleAction = ruleAction;
    // var statustext = ''; // TODO
    item.setAttribute("class", `rpc-od-item ${cssClass}`);
    const canonicalRule = Ruleset.rawRuleToCanonicalString(ruleData);
    if (self._ruleChangeQueues[ruleAction]) {
      if (self._ruleChangeQueues[ruleAction][canonicalRule]) {
        item.setAttribute("selected-rule", "true");
      }
    }
    return item;
  };

  self._addMenuItemRemoveAllowRule = function(
      list, rawRule,
      subscriptionOverride
  ) {
    if (rawRule.o && rawRule.d) {
      return self._addMenuItemStopAllowingOriginToDest(
          list, rawRule,
          subscriptionOverride
      );
    } else if (rawRule.o) {
      return self._addMenuItemStopAllowingOrigin(
          list, rawRule,
          subscriptionOverride
      );
    } else if (rawRule.d) {
      return self._addMenuItemStopAllowingDest(
          list, rawRule,
          subscriptionOverride
      );
    } else {
      // eslint-disable-next-line no-throw-literal
      throw "Invalid rule data: no origin or destination parts.";
    }
  };

  self._addMenuItemRemoveDenyRule = function(
      list, rawRule,
      subscriptionOverride
  ) {
    if (rawRule.o && rawRule.d) {
      return self._addMenuItemStopDenyingOriginToDest(
          list, rawRule,
          subscriptionOverride
      );
    } else if (rawRule.o) {
      return self._addMenuItemStopDenyingOrigin(
          list, rawRule,
          subscriptionOverride
      );
    } else if (rawRule.d) {
      return self._addMenuItemStopDenyingDest(
          list, rawRule,
          subscriptionOverride
      );
    } else {
      // eslint-disable-next-line no-throw-literal
      throw "Invalid rule data: no origin or destination parts.";
    }
  };

  self._populateDetailsRemoveAllowRules = function(list) {
    // TODO: can we avoid calling getAllowedRequests here and reuse a result
    // from calling it earlier?

    let reqSet = Requests.getAllowedRequests(
        self._currentlySelectedOrigin, self._allRequestsOnDocument
    );
    let requests = reqSet.getAllMergedOrigins();

    // var rules = {};

    let userRules = {};
    let subscriptionRules = {};

    // reqSet.print('allowedRequests');

    // TODO: there is no dest if no dest is selected (origin only).
    // var destBase = DomainUtil.getBaseDomain(
    //      self._currentlySelectedDest);

    for (let destBase in requests) {
      if (self._currentlySelectedDest &&
          self._currentlySelectedDest !== destBase) {
        continue;
      }

      for (let destIdent in requests[destBase]) {
        const destinations = requests[destBase][destIdent];
        for (let destUri in destinations) {
          // This will be null when the request was denied because of a default
          // allow rule. However about any other time?
          // TODO: we at least in default allow mode, we need to give an option
          // to add a deny rule for these requests.
          if (!destinations[destUri]) {
            log.log(`${"destinations[destUri] is null or undefined for " +
                "destUri: "}${destUri}`);
            continue;
          }

          const results = destinations[destUri][0]; // TODO: Do not look only
          // at the first RequestResult object, but at all. (there might be
          // several requests with identical origin and destination URI.)

          for (let i in results.matchedAllowRules) {
            let [ruleset, match] = results.matchedAllowRules[i];
            let rawRule = Ruleset.matchToRawRule(match);

            if (!self._currentlySelectedDest) {
              if (rawRule.d && rawRule.d.h) {
                continue;
              }
            }

            let rawRuleStr = Ruleset.rawRuleToCanonicalString(rawRule);
            // log.info("matched allow rule: " + rawRuleStr);
            // This is how we remove duplicates: if two rules have the same
            // canonical string, they'll have in the same key.
            if (ruleset.userRuleset) {
              userRules[rawRuleStr] = rawRule;
            } else {
              subscriptionRules[rawRuleStr] = rawRule;
            }
          }
        }
      }
    }

    for (let i in userRules) {
      self._addMenuItemRemoveAllowRule(list, userRules[i], false);
    }
    // TODO: for subscription rules, we need the effect of the menu item to be
    // adding a deny rule instead of removing an allow rule. However, the text
    // used for the item needs to be the same as removing an allow rule.
    for (let i in subscriptionRules) {
      self._addMenuItemRemoveAllowRule(list, subscriptionRules[i], true);
    }
  };

  self._populateDetailsRemoveDenyRules = function(list) {
    // TODO: can we avoid calling getDeniedRequests here and reuse a result
    // from calling it earlier?

    let reqSet = Requests.getDeniedRequests(
        self._currentlySelectedOrigin, self._allRequestsOnDocument
    );
    let requests = reqSet.getAllMergedOrigins();

    // var rules = {};

    let userRules = {};
    let subscriptionRules = {};

    reqSet.print("deniedRequests");

    // TODO: there is no dest if no dest is selected (origin only).
    // var destBase = DomainUtil.getBaseDomain(
    //     self._currentlySelectedDest);

    for (let destBase in requests) {
      if (self._currentlySelectedDest &&
        self._currentlySelectedDest !== destBase) {
        continue;
      }

      for (let destIdent in requests[destBase]) {
        let destinations = requests[destBase][destIdent];
        for (let destUri in destinations) {
          // This will be null when the request was denied because of a default
          // deny rule. However about any other time?
          // TODO: we at least in default deny mode, we need to give an option
          // to add a allow rule for these requests.
          if (!destinations[destUri]) {
            log.log(`${"destinations[destUri] is null or undefined " +
                "for destUri: "}${destUri}`);
            continue;
          }

          let results = destinations[destUri][0]; // TODO: Do not look only
          // at the first RequestResult object, but at all. (there may be
          // several requests with identical origin and destination URI.)

          for (let i in results.matchedDenyRules) {
            let [ruleset, match] = results.matchedDenyRules[i];
            let rawRule = Ruleset.matchToRawRule(match);

            if (!self._currentlySelectedDest) {
              if (rawRule.d && rawRule.d.h) {
                continue;
              }
            }

            let rawRuleStr = Ruleset.rawRuleToCanonicalString(rawRule);
            // log.info("matched allow rule: " + rawRuleStr);
            // This is how we remove duplicates: if two rules have the same
            // canonical string, they'll have in the same key.
            if (ruleset.userRuleset) {
              userRules[rawRuleStr] = rawRule;
            } else {
              subscriptionRules[rawRuleStr] = rawRule;
            }
          }
        }
      }
    }

    for (let i in userRules) {
      self._addMenuItemRemoveDenyRule(list, userRules[i], false);
    }
    // TODO: for subscription rules, we need the effect of the menu item to be
    // adding an allow rule instead of removing a deny rule. However, the text
    // used for the item needs to be the same as removing a deny rule.
    for (let i in subscriptionRules) {
      self._addMenuItemRemoveDenyRule(list, subscriptionRules[i], true);
    }
  };

  self._populateDetailsAddSubdomainAllowRules = function(list) {
    let origin = self._currentlySelectedOrigin;

    // TODO: can we avoid calling getDeniedRequests here and reuse a result
    // from calling it earlier?

    let reqSet = Requests.getDeniedRequests(
        self._currentlySelectedOrigin, self._allRequestsOnDocument
    );
    let requests = reqSet.getAllMergedOrigins();

    let destHosts = {};

    for (let destBase in requests) {
      if (self._currentlySelectedDest &&
          self._currentlySelectedDest !== destBase) {
        continue;
      }
      for (let destIdent in requests[destBase]) {
        let destinations = requests[destBase][destIdent];
        for (let destUri in destinations) {
          destHosts[DomainUtil.getHost(destUri)] = null;
        }
      }
    }

    let mayPermRulesBeAdded = WindowUtils.mayPermanentRulesBeAdded(
        window, rp.storage
    );

    for (let destHost in destHosts) {
      let ruleData = {
        "o": {
          "h": self._addWildcard(origin),
        },
        "d": {
          "h": destHost,
        },
      };
      if (!rp.policy.ruleExists(C.RULE_ACTION_ALLOW, ruleData) &&
          !rp.policy.ruleExists(C.RULE_ACTION_DENY, ruleData)) {
        if (mayPermRulesBeAdded === true) {
          self._addMenuItemAllowOriginToDest(list, ruleData);
        }
        self._addMenuItemTempAllowOriginToDest(list, ruleData);
      }

      let destOnlyRuleData = {
        "d": {
          "h": destHost,
        },
      };
      if (!rp.policy.ruleExists(C.RULE_ACTION_ALLOW, destOnlyRuleData) &&
          !rp.policy.ruleExists(C.RULE_ACTION_DENY, destOnlyRuleData)) {
        if (mayPermRulesBeAdded === true) {
          self._addMenuItemAllowDest(list, destOnlyRuleData);
        }
        self._addMenuItemTempAllowDest(list, destOnlyRuleData);
      }
    }
  };

  // eslint-disable-next-line no-param-reassign
  window.rpcontinued.menu = self;
}
