/// Kinds of input a mode can require from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputKind {
    Domain,
    Ip,
    Url,
    File,
    Ports,
    Target,
    Username,
    Password,
    Interface,
    Hash,
    Wordlist,
    Payload,
    Session,
    Lhost,
    Lport,
    Custom(&'static str, &'static str),
}

impl InputKind {
    /// Human-readable prompt label shown to the user.
    pub fn label(self) -> &'static str {
        match self {
            Self::Domain    => "Domain",
            Self::Ip        => "IP / CIDR",
            Self::Url       => "URL",
            Self::File      => "File path",
            Self::Ports     => "Ports (e.g. 80,443)",
            Self::Target    => "Target (IP/domain/URL)",
            Self::Username  => "Username",
            Self::Password  => "Password",
            Self::Interface => "Interface (e.g. wlan0, eth0)",
            Self::Hash      => "Hash value",
            Self::Wordlist  => "Wordlist path",
            Self::Payload   => "Payload path",
            Self::Session   => "Session ID",
            Self::Lhost     => "Listener IP (LHOST)",
            Self::Lport     => "Listener port (LPORT)",
            Self::Custom(label, _) => label,
        }
    }

    /// Placeholder key used inside cmd_template strings.
    pub fn placeholder(self) -> &'static str {
        match self {
            Self::Domain    => "domain",
            Self::Ip        => "ip",
            Self::Url       => "url",
            Self::File      => "file",
            Self::Ports     => "ports",
            Self::Target    => "target",
            Self::Username  => "username",
            Self::Password  => "password",
            Self::Interface => "interface",
            Self::Hash      => "hash",
            Self::Wordlist  => "wordlist",
            Self::Payload   => "payload",
            Self::Session   => "session",
            Self::Lhost     => "lhost",
            Self::Lport     => "lport",
            Self::Custom(_, ph) => ph,
        }
    }
}


/// Expected output format — drives parser selection and file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Newline-separated list of values (subdomains, IPs, URLs …).
    Lines,
    /// JSON document.
    Json,
    /// XML document.
    Xml,
    /// Nmap-style output (open ports, service info).
    Nmap,
    /// Comma-separated values.
    Csv,
    /// Unstructured / binary — display raw.
    Raw,
}

/// One operational mode for a security tool.
pub struct Mode {
    /// Short, descriptive name shown in the menu (2–4 words).
    pub name: &'static str,
    /// Shell command template.  Placeholders: {domain}, {ip}, {url},
    /// {file}, {target}, {ports}, {value}, {output_file}, {timestamp}.
    pub cmd_template: &'static str,
    /// Ordered list of inputs the user must supply before the command runs.
    pub inputs: &'static [InputKind],
    /// How the tool's output should be parsed and displayed.
    pub output_format: OutputFormat,
    /// File extension for the saved output file.
    pub file_ext: &'static str,
}

/// A security tool with one or more operational modes.
pub struct Tool {
    /// Display name shown in the menu.
    pub name: &'static str,
    /// Executable name looked up in PATH.
    pub binary: &'static str,
    /// Brief description of the tool's capabilities.
    pub description: &'static str,
    /// At least four distinct modes.
    pub modes: &'static [Mode],
}

/// A top-level category grouping related tools.
pub struct Category {
    /// Display name shown in the category menu.
    pub name: &'static str,
    /// All tools belonging to this category.
    pub tools: &'static [Tool],
}
