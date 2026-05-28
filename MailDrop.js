/**
 * MailDrop - A Modern Firewall for Your Inbox
 * Hard deletion utility using Gmail API and modular configuration.
 * * Based on the original Spam Zero concept by spamzero, modified to 
 * support API-level hard deletion and modern emoji/reaction parsing.
 */

// ==========================================
// CONFIGURATION BLOCK
// Add or remove items here.
// ==========================================
var CONFIG = {
    // 1. Exact phrases anywhere in the raw email headers or body
    exactPhrases: [
        "X-Mailer: badmailer", 
        "To: victim@", 
        "List-Owner: <mailto:spammer@example.com>"
    ],

    // 2. Custom Regex for changing patterns
    regexPatterns: [
        /X-Google-Sender-Delegation:\s*[a-zA-Z]{10}\b/i, 
        /From:[^\n]*@[a-zA-Z]+\.us\b/i 
    ],

    // 3. Junk Top-Level Domains (TLDs)
    // You can type these exactly as they appear (e.g., "co.uk" or "web.id").
    // The script will safely escape the dots automatically.
    junkTlds: [
        "club", 
        "date", 
        "top", 
        "xyz", 
        "trade", 
        "party", 
        "life", 
        "pro",
        "web.id"
    ],

    // 4. Shortened URLs found in the body
    shortenedUrls: [
        /bit\.ly/i, 
        /tinyurl\.com/i, 
        /goo\.gl/i
    ],

    // 5. Profanity or common spam trigger words
    profanity: [
        /slut/i, 
        /f\.ck/i, 
        /s\.ck/i, 
        /c\.ck/i, 
        /h\.\.kup/i, 
        /cum/i, 
        /p\.rn/i, 
        /s[e3\*\.]xy?/i
    ],

    // Script Settings
    maxThreadsToProcess: 100, // Keeps script under Google's 6-minute execution limit
    isDebugMode: true         // Set to false to disable console logging
};

// ==========================================
// CORE LOGIC - DO NOT MODIFY
// ==========================================

var threads = GmailApp.search('in:spam', 0, CONFIG.maxThreadsToProcess);
var actions = ["HARD_DELETE"];

var rules = [
    function(m, raw) {
        "Config: Exact Phrases"
        var rawContent = m.getRawContent();
        return CONFIG.exactPhrases.some(function(phrase) {
            return rawContent.includes(phrase);
        });
    },

    function(m, raw) {
        "Config: Custom Regex Patterns"
        var rawContent = m.getRawContent();
        return CONFIG.regexPatterns.some(function(regex) {
            return regex.test(rawContent);
        });
    },

    function(m, raw) {
        "Config: Junk TLDs (Sender or URL)"
        var escapedTlds = CONFIG.junkTlds.map(function(tld) { return tld.replace(/\./g, "\\."); });
        var tldPattern = "\\.(" + escapedTlds.join("|") + ")";
        
        var fromRegex = new RegExp(tldPattern + ">?$", "i");
        var urlRegex = new RegExp("(https?|www).+" + tldPattern + "(\\b|/)", "i");
        
        return Boolean(
            m.getFrom().match(fromRegex) || 
            (raw.body && raw.body.match(urlRegex))
        );
    },

    function(m, raw) {
        "Modern Unicode Emojis in Subject"
        var subject = m.getSubject();
        return subject && subject.match(/\p{Extended_Pictographic}/u);
    },

    function(m, raw) {
        "Gmail Emoji Reaction Abuse"
        return m.getRawContent().includes("text/vnd.google.email-reaction+json");
    },

    function(m, raw) {
        "From *.ru + image attachment"
        var ruSender = m.getFrom().match(/\.ru>?$/);
        var withImageAttachment = MessageHelper.hasImageAttachment(m);
        return ruSender && withImageAttachment;
    },

    function(m, raw) {
        "Config: Profanity filter"
        for (var i = 0; i < CONFIG.profanity.length; i++) {
            var regex = CONFIG.profanity[i];
            if ((raw.headers.subject && raw.headers.subject.match(regex)) || 
                (raw.body && raw.body.match(regex)) || 
                (raw.headers.from && raw.headers.from.match(regex))) {
                return true;
            }
        }
        return false;
    },

    function(m, raw) {
        "Has link to Dropbox in body"
        return raw.body && raw.body.match(/dl\.dropboxusercontent\.com/i);
    },

    function(m, raw) {
        "Config: Shortened URLs in body"
        for (var i = 0; i < CONFIG.shortenedUrls.length; i++) {
            if (raw.body && raw.body.match(CONFIG.shortenedUrls[i])) {
                return true;
            }
        }
        return false;
    }
];

// --- Utilities & Parsers ---

var MessageHelper = {
    hasImageAttachment: function(message) {
        var attachments = message.getAttachments();
        for (var i = 0; i < attachments.length; i++) {
            if (attachments[i].getContentType().match(/image/)) {
                return true;
            }
        }
        return false;
    }
};

var getLogger = function() {
    if (CONFIG.isDebugMode) {
        return console; 
    } else {
        return { log: function () {} };
    }
};

var anyMessageMatchesAnyRuleInThread = function(thread) {
    var messages = thread.getMessages();

    for (var i = 0; i < messages.length; i++) {
        var raw = parseRawContent(messages[i].getRawContent());

        for (var j = 0; j < rules.length; j++) {
            if (rules[j](messages[i], raw)) {
                var ruleDescription = parseRuleDescription(rules[j]);
                getLogger().log('Match found! Subject: "' + messages[i].getSubject() + '" matched rule "' + (ruleDescription ? ruleDescription : j) + '"');
                return true; 
            }
        }
    }
    return false;
};

var parseRawContent = function(rawContent) {
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
            result.body += lines[i];
        }
    }

    if (result.headers["content-transfer-encoding"] === "base64") {
        try {
            result.body = Utilities.newBlob(Utilities.base64Decode(result.body)).getDataAsString();
        } catch (err) {
            getLogger().log("Could not base64 decode body.");
        }
    }
    return result;
};

var parseRuleDescription = function(func) {
    var lines = func.toString().split("\n");
    for (var i = 0; i < lines.length; i++) {
        var matches = lines[i].trim().match(/^"([^"]+)";?$/);
        if (matches) return matches[1];
    }
    return "";
};

// --- Custom Actions ---

var HardDeleteAction = function () {
    this.run = function (thread) {
        try {
            Gmail.Users.Threads.remove('me', thread.getId());
            getLogger().log('Thread permanently deleted.');
        } catch (e) {
            getLogger().log("Failed to hard delete thread: " + e.message);
        }
    };
};

var ActionFactory = {
    create: function(actionName) {
        if (actionName === "HARD_DELETE") return new HardDeleteAction();
        throw "Unknown action: " + actionName;
    }
};

var runActionsOnThread = function(thread) {
    for (var i = 0; i < actions.length; i++) {
        var action = ActionFactory.create(actions[i]);
        getLogger().log('Running action "' + actions[i] + '"');
        action.run(thread);
    }
};

function main() {
    getLogger().log("Starting scan of " + threads.length + " threads...");

    for (var i = 0; i < threads.length; i++) {
        getLogger().log("--- Processing thread " + (i + 1) + " ---");

        if (anyMessageMatchesAnyRuleInThread(threads[i])) {
            runActionsOnThread(threads[i]);
        } else {
            getLogger().log("No rules matched. Left in Spam.");
        }
    }
    
    getLogger().log("Scan complete.");
}
