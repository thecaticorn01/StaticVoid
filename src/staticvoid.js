/**
 * StaticVoid - API-Driven Gmail Spam Filtering
 * License: GNU GPLv3
 * * Inspects raw MIME payloads to permanently delete messages matching 
 * configurable blocklist criteria, bypassing the trash folder entirely.
 */

var CONFIG = {
  settings: {
    dryRun: false,           // Set to true to log matches without deleting
    maxThreads: 100,         // Limits thread batches to prevent script timeouts
    debug: true              // Enables logging to the execution console
  },
  
  // CONTROL LAYER SWITCHES
  layers: {
    layer1Metadata: true,    // Evaluates envelope metadata (Subject, From)
    layer2DeepScan: true     // Evaluates raw payload data (MIME text, body URLs)
  },

  // USER CONFIGURATION: WHITELIST
  whitelist: {
    enabled: true,
    allowUnspam: true,       // Moves whitelisted mail from Spam back to Inbox
    
    trustedEmails: [
      "alerts@yourbank.com",
      "noreply@github.com"
    ],
    trustedDomains: [
      "edu", 
      "gov"
    ],
    trustedKeywords: [
      "your order confirmation",
      "two-factor authentication",
      "password reset"
    ]
  },

  // USER CONFIGURATION: BLOCKLISTS
  features: {
    unicodeEmojis: {
      enabled: true          // Deletes emails with emojis in the subject line
    },
    senderJunkTlds: {
      enabled: true,
      list: ["club", "date", "top", "xyz", "trade", "party", "life", "pro", "web.id"]
    },
    exactPhrases: {
      enabled: true,
      list: [
        "X-Mailer: SpammerEngineV1",
        "To: generic-honeypot@",
        "List-Owner: <mailto:shady-unsub@example.com>",
        "@malicious-tracking-network.biz"
      ]
    },
    regexPatterns: {
      enabled: true,
      list: [
        /X-Custom-Spam-Header:\s*[a-zA-Z]{10}\b/i,
        /From:[^\n]*@[a-zA-Z]+\.us\b/i
      ]
    },
    bodyJunkTlds: {
      enabled: true          // Reuses senderJunkTlds list to scan body URLs
    },
    emojiReactions: {
      enabled: true          // Blocks Gmail emoji reaction exploit patterns
    },
    ruSenderWithImages: {
      enabled: true          // Blocks .ru senders carrying physical image attachments
    },
    shortenedUrls: {
      enabled: true,
      list: [/bit\.ly/i, /tinyurl\.com/i, /goo\.gl/i]
    },
    profanityFilter: {
      enabled: true,
      list: [/slut/i, /f\.ck/i, /s\.ck/i, /c\.ck/i, /h\.\.kup/i, /cum/i, /p\.rn/i, /s[e3\*\.]xy?/i]
    },
    sizeGuard: {
      enabled: true,
      maxSizeBytes: 150000   // Skips heavy MIME parsing on abnormally large payloads
    }
  }
};

var activeLayer1Rules = [];
var activeLayer2Rules = [];

function initActiveRules() {
  activeLayer1Rules = [];
  activeLayer2Rules = [];

  if (CONFIG.layers.layer1Metadata) {
    if (CONFIG.features.unicodeEmojis.enabled) {
      activeLayer1Rules.push({
        id: "EMOJI_SUBJ",
        run: function(m) {
          var subject = m.getSubject();
          return subject && subject.match(/\p{Extended_Pictographic}/u);
        }
      });
    }
    if (CONFIG.features.senderJunkTlds.enabled) {
      activeLayer1Rules.push({
        id: "SENDER_TLD",
        run: function(m) {
          var escaped = CONFIG.features.senderJunkTlds.list.map(function(tld) { return tld.replace(/\./g, "\\."); });
          var regex = new RegExp("\\.(" + escaped.join("|") + ")>?$", "i");
          return Boolean(m.getFrom().match(regex));
        }
      });
    }
  }

  if (CONFIG.layers.layer2DeepScan) {
    if (CONFIG.features.exactPhrases.enabled) {
      activeLayer2Rules.push({
        id: "EXACT_PHRASE",
        run: function(m, raw) {
          return CONFIG.features.exactPhrases.list.some(function(phrase) {
            return m.getRawContent().includes(phrase);
          });
        }
      });
    }
    if (CONFIG.features.regexPatterns.enabled) {
      activeLayer2Rules.push({
        id: "REGEX_MATCH",
        run: function(m, raw) {
          return CONFIG.features.regexPatterns.list.some(function(regex) {
            return regex.test(m.getRawContent());
          });
        }
      });
    }
    if (CONFIG.features.bodyJunkTlds.enabled && CONFIG.features.senderJunkTlds.enabled) {
      activeLayer2Rules.push({
        id: "BODY_TLD",
        run: function(m, raw) {
          var escaped = CONFIG.features.senderJunkTlds.list.map(function(tld) { return tld.replace(/\./g, "\\."); });
          var regex = new RegExp("(https?|www).+\\.(" + escaped.join("|") + ")(\\b|/)", "i");
          return Boolean(raw.body && raw.body.match(regex));
        }
      });
    }
    if (CONFIG.features.emojiReactions.enabled) {
      activeLayer2Rules.push({
        id: "EMOJI_REACTION",
        run: function(m, raw) {
          return m.getRawContent().includes("text/vnd.google.email-reaction+json");
        }
      });
    }
    if (CONFIG.features.ruSenderWithImages.enabled) {
      activeLayer2Rules.push({
        id: "RU_IMAGE",
        run: function(m, raw) {
          if (!m.getFrom().match(/\.ru>?$/)) return false;
          var attachments = m.getAttachments();
          for (var i = 0; i < attachments.length; i++) {
            if (attachments[i].getContentType().match(/image/)) return true;
          }
          return false;
        }
      });
    }
    if (CONFIG.features.shortenedUrls.enabled) {
      activeLayer2Rules.push({
        id: "SHORT_URL",
        run: function(m, raw) {
          return CONFIG.features.shortenedUrls.list.some(function(regex) {
            return raw.body && raw.body.match(regex);
          });
        }
      });
    }
    if (CONFIG.features.profanityFilter.enabled) {
      activeLayer2Rules.push({
        id: "PROFANITY",
        run: function(m, raw) {
          return CONFIG.features.profanityFilter.list.some(function(regex) {
            return (raw.headers.subject && raw.headers.subject.match(regex)) || 
                   (raw.body && raw.body.match(regex)) || 
                   (raw.headers.from && raw.headers.from.match(regex));
          });
        }
      });
    }
  }
}

function checkWhitelist(thread, firstMessage) {
  if (!CONFIG.whitelist.enabled) return false;

  var fromField = firstMessage.getFrom().toLowerCase();
  var subjectField = firstMessage.getSubject().toLowerCase();

  for (var i = 0; i < CONFIG.whitelist.trustedEmails.length; i++) {
    if (fromField.includes(CONFIG.whitelist.trustedEmails[i].toLowerCase())) return true;
  }
  for (var j = 0; j < CONFIG.whitelist.trustedDomains.length; j++) {
    var domainRegex = new RegExp("\\." + CONFIG.whitelist.trustedDomains[j].replace(/\./g, "\\.") + ">?$", "i");
    if (fromField.match(domainRegex)) return true;
  }
  for (var k = 0; k < CONFIG.whitelist.trustedKeywords.length; k++) {
    if (subjectField.includes(CONFIG.whitelist.trustedKeywords[k].toLowerCase())) return true;
  }
  return false;
}

function processThread(thread) {
  var messages = thread.getMessages();
  if (messages.length === 0) return;
  
  var firstMsg = messages[0];

  if (checkWhitelist(thread, firstMsg)) {
    if (CONFIG.whitelist.allowUnspam && thread.isInSpam()) {
      if (!CONFIG.settings.dryRun) {
        GmailApp.moveThreadToInbox(thread);
        thread.markUnread();
      }
      log('[Whitelist] Secure override triggered. Moving thread out of Spam: "' + firstMsg.getSubject() + '"');
    }
    return;
  }

  for (var i = 0; i < messages.length; i++) {
    var msg = messages[i];

    if (CONFIG.features.sizeGuard.enabled && msg.getRawContent().length > CONFIG.features.sizeGuard.maxSizeBytes) {
      log('[SafetyGuard] Skipping heavy operations on abnormally massive payload segment.');
      continue;
    }

    // Layer 1 Check
    for (var j = 0; j < activeLayer1Rules.length; j++) {
      if (activeLayer1Rules[j].run(msg)) {
        log('[Layer 1 Matching] Drop rule triggered: ' + activeLayer1Rules[j].id + ' on Subject: "' + msg.getSubject() + '"');
        executeDropAction(thread);
        return;
      }
    }

    // Layer 2 Check
    if (CONFIG.layers.layer2DeepScan && activeLayer2Rules.length > 0) {
      var rawParsed = parseRawContent(msg.getRawContent());

      for (var k = 0; k < activeLayer2Rules.length; k++) {
        if (activeLayer2Rules[k].run(msg, rawParsed)) {
          log('[Layer 2 Deep Scan] Drop rule triggered: ' + activeLayer2Rules[k].id + ' on Subject: "' + msg.getSubject() + '"');
          executeDropAction(thread);
          return;
        }
      }
    }
  }
}

function parseRawContent(rawContent) {
  var lines = rawContent.split("\n");
  var result = { headers: {}, body: "" };
  var currentHeaderKey = null;
  var headerParsed = false;

  for (var i = 0; i < lines.length; i++) {
    if (lines[i].trim() === "") {
      if (result.headers.date === undefined) continue;
      headerParsed = true;
      continue;
    }

    if (!headerParsed) {
      var headerParts = lines[i].match(/^([-a-z]+):(.*)/i);
      if (headerParts) {
        currentHeaderKey = headerParts[1].toLowerCase();
        result.headers[currentHeaderKey] = headerParts[2].trim();
      } else if (currentHeaderKey) {
        result.headers[currentHeaderKey] += " " + lines[i].trim();
      }
    } else {
      result.body += lines[i] + "\n";
    }
  }

  if (result.headers["content-transfer-encoding"] === "base64") {
    try {
      result.body = Utilities.newBlob(Utilities.base64Decode(result.body)).getDataAsString();
    } catch (err) {
      log("[Parser] Base64 body decoding fallback applied.");
    }
  }
  return result;
}

function executeDropAction(thread) {
  if (CONFIG.settings.dryRun) {
    log('[DryRun] Firewall match validated. Simulation Mode - no action taken.');
    return;
  }
  try {
    Gmail.Users.Threads.remove('me', thread.getId());
    log('[Firewall] API Drop Complete. Thread permanently purged.');
  } catch (e) {
    log("[Error] Target thread could not be dropped: " + e.message);
  }
}

function log(msg) {
  if (CONFIG.settings.debug) console.log(msg);
}

function main() {
  initActiveRules();
  var threadsToProcess = GmailApp.search('in:spam', 0, CONFIG.settings.maxThreads);
  log("StaticVoid initialized. Evaluating " + threadsToProcess.length + " targets...");
  
  try {
    for (var i = 0; i < threadsToProcess.length; i++) {
      processThread(threadsToProcess[i]);
    }
  } catch (globalFault) {
    log("[Fault] Script cycle interrupted cleanly: " + globalFault.message);
  }
  log("Firewall sweep complete.");
}

function doGet() {
  return HtmlService.createTemplateFromFile('src/dashboard')
      .evaluate()
      .setTitle('StaticVoid Command Center')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function getDashboardMetrics() {
  initActiveRules();
  var spamCount = 0;
  try {
    spamCount = GmailApp.getSpamThreadsCount();
  } catch(e){}
  
  return {
    dryRun: CONFIG.settings.dryRun,
    layer1Count: activeLayer1Rules.length,
    layer2Count: activeLayer2Rules.length,
    whitelistCount: CONFIG.whitelist.trustedEmails.length + CONFIG.whitelist.trustedDomains.length,
    spamThreadsCurrently: spamCount
  };
}

function triggerManualScan() {
  main();
  return "Scan successfully completed. Check the Apps Script console for runtime logs.";
}