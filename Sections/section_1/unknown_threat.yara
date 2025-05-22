rule unknown_threat {
        meta:
                Author = "@MMM"
                Description = "the rule detects the presence of a specified threat in South Dakota's servers"
        strings:
                $domain = "darkl0rd.com:7758"
                $Script = "SSH-T|SSH-One" nocase
        condition:
                $domain or $Script

}