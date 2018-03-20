/*
 * ***** BEGIN LICENSE BLOCK *****
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * ***** END LICENSE BLOCK *****
 */

// code origin:
// tslint:disable-next-line:max-line-length
// https://github.com/wrangr/psl/blob/ed433eac2e6a3e37d38130565df8750aad437c05/index.js

import { IModule, Module } from "lib/classes/module";
import { Log } from "models/log";

import * as PunycodeModule from "lib/third-party/punycode";
type Punycode = typeof PunycodeModule;

interface IRule {
  rule: string;
  suffix: string;
  punySuffix: string | -1;
  wildcard: boolean;
  exception: boolean;
}

interface IParsed {
  input: string;
  tld: string | null | undefined;
  sld: string | null | undefined;
  domain: string | null | undefined;
  subdomain: string | null | undefined;
  listed: boolean;
}

//
// Error codes and messages.
//
// tslint:disable:object-literal-sort-keys
export const ERROR_CODES = {
  DOMAIN_TOO_SHORT: "Domain name too short.",
  DOMAIN_TOO_LONG: "Domain name too long. " +
      "It should be no more than 255 chars.",
  LABEL_STARTS_WITH_DASH: "Domain name label can not start with a dash.",
  LABEL_ENDS_WITH_DASH: "Domain name label can not end with a dash.",
  LABEL_TOO_LONG: "Domain name label should be at most 63 chars long.",
  LABEL_TOO_SHORT: "Domain name label should be at least 1 character long.",
  LABEL_INVALID_CHARS: "Domain name label can only contain alphanumeric " +
      "characters or dashes.",
};
// tslint:enable:object-literal-sort-keys

export class EffectiveTLDService extends Module {
  private rules: IRule[];
  constructor(
      log: Log,
      private punycode: Punycode,
      rawPsl: string[],
  ) {
    super("app.services.eTLD", log);
    this.rules = rawPsl.map((rule) => {
      // tslint:disable:object-literal-sort-keys
      return {
        rule,
        suffix: rule.replace(/^(\*\.|\!)/, ""),
        punySuffix: -1,
        wildcard: rule.charAt(0) === "*",
        exception: rule.charAt(0) === "!",
      } as IRule;
    });
  }

  //
  // Parse domain.
  //
  public parse(input: string) {

    if (typeof input !== "string") {
      throw new TypeError("Domain name must be a string.");
    }

    // Force domain to lowercase.
    let domain = input.slice(0).toLowerCase();

    // Handle FQDN.
    // TODO: Simply remove trailing dot?
    if (domain.charAt(domain.length - 1) === ".") {
      domain = domain.slice(0, domain.length - 1);
    }

    // Validate and sanitise input.
    const error = this.validate(domain);
    if (error) {
      return {
        input,
        error: {
          message: ERROR_CODES[error],
          code: error,
        },
      };
    }

    const parsed: IParsed = {
      input,
      tld: null,
      sld: null,
      domain: null,
      subdomain: null,
      listed: false,
    };

    const domainParts = domain.split(".");

    // Non-Internet TLD
    if (domainParts[domainParts.length - 1] === "local") {
      return parsed;
    }

    const handlePunycode = () => {
      if (!/xn--/.test(domain)) {
        return parsed;
      }
      if (parsed.domain) {
        parsed.domain = this.punycode.toASCII(parsed.domain);
      }
      if (parsed.subdomain) {
        parsed.subdomain = this.punycode.toASCII(parsed.subdomain);
      }
      return parsed;
    };

    const rule = this.findRule(domain);

    // Unlisted tld.
    if (!rule) {
      if (domainParts.length < 2) {
        return parsed;
      }
      parsed.tld = domainParts.pop();
      parsed.sld = domainParts.pop();
      parsed.domain = [parsed.sld, parsed.tld].join(".");
      if (domainParts.length) {
        parsed.subdomain = domainParts.pop();
      }
      return handlePunycode();
    }

    // At this point we know the public suffix is listed.
    parsed.listed = true;

    const tldParts = rule.suffix.split(".");
    const privateParts = domainParts.slice(0,
        domainParts.length - tldParts.length);

    if (rule.exception) {
      const part = tldParts.shift();
      if (part) privateParts.push(part);
    }

    parsed.tld = tldParts.join(".");

    if (!privateParts.length) {
      return handlePunycode();
    }

    if (rule.wildcard) {
      tldParts.unshift(privateParts.pop()!);
      parsed.tld = tldParts.join(".");
    }

    if (!privateParts.length) {
      return handlePunycode();
    }

    parsed.sld = privateParts.pop();
    parsed.domain = [parsed.sld,  parsed.tld].join(".");

    if (privateParts.length) {
      parsed.subdomain = privateParts.join(".");
    }

    return handlePunycode();
  }

  //
  // Get domain.
  //
  public get(domain: string | undefined): string | null {
    if (!domain) {
      return null;
    }
    const parsed = this.parse(domain);
    if (!("domain" in parsed)) return null;
    return (parsed as IParsed).domain || null;
  }

  //
  // Check whether domain belongs to a known public suffix.
  //
  public isValid(domain: string): boolean {
    const parsed = this.parse(domain);
    return Boolean(
        (parsed as IParsed).domain &&
        (parsed as IParsed).listed,
    );
  }

  //
  // private
  //

  //
  // Check is given string ends with `suffix`.
  //
  private endsWith(str: string, suffix: string) {
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
  }

  //
  // Find rule for a given domain.
  //
  private findRule(domain: string) {
    const punyDomain = this.punycode.toASCII(domain);
    return this.rules.reduce((memo, rule) => {

      if (rule.punySuffix === -1) {
        rule.punySuffix = this.punycode.toASCII(rule.suffix);
      }
      if (
          !this.endsWith(punyDomain, "." + rule.punySuffix) &&
          punyDomain !== rule.punySuffix
      ) {
        return memo;
      }
      // This has been commented out as it never seems to run. This is because
      // sub tlds always appear after their parents and we never find a shorter
      // match.
      // if (memo) {
      //  var memoSuffix = this.punycode.toASCII(memo.suffix);
      //  if (memoSuffix.length >= punySuffix.length) {
      //    return memo;
      //  }
      // }
      return rule;
    }, null);
  }

  //
  // Validate domain name and throw if not valid.
  //
  // From wikipedia:
  //
  // Hostnames are composed of series of labels concatenated with dots, as are
  // all domain names. Each label must be between 1 and 63 characters long, and
  // the entire hostname (including the delimiting dots) has a maximum of 255
  // chars.
  //
  // Allowed chars:
  //
  // * `a-z`
  // * `0-9`
  // * `-` but not as a starting or ending character
  // * `.` as a separator for the textual portions of a domain name
  //
  // * http://en.wikipedia.org/wiki/Domain_name
  // * http://en.wikipedia.org/wiki/Hostname
  //
  private validate(input: string) {

    // Before we can validate we need to take care of IDNs with unicode chars.
    const ascii = this.punycode.toASCII(input);

    if (ascii.length < 1) {
      return "DOMAIN_TOO_SHORT";
    }
    if (ascii.length > 255) {
      return "DOMAIN_TOO_LONG";
    }

    // Check each part's length and allowed chars.
    const labels = ascii.split(".");

    for (const label of labels) {
      if (!label.length) {
        return "LABEL_TOO_SHORT";
      }
      if (label.length > 63) {
        return "LABEL_TOO_LONG";
      }
      if (label.charAt(0) === "-") {
        return "LABEL_STARTS_WITH_DASH";
      }
      if (label.charAt(label.length - 1) === "-") {
        return "LABEL_ENDS_WITH_DASH";
      }
      if (!/^[a-z0-9\-]+$/.test(label)) {
        return "LABEL_INVALID_CHARS";
      }
    }
  }
}

export interface IEffectiveTLDService extends IModule {
  parse: typeof EffectiveTLDService.prototype.parse;
  get: typeof EffectiveTLDService.prototype.get;
  isValid: typeof EffectiveTLDService.prototype.isValid;
}
