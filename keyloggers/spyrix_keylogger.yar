import "math"

rule spyrix_keylogger {
    meta:
        date = "2022-10-11"
        author = "@billyaustintx"
        description = "Detects Spyrix keylogger commonly used by jealous spouses and malicious actors."
        ref1 = "https://rziju0752s.spyrixweb.com"
        hash1 = "052b9f9e78cc2ae81efcd0d449da97d7"
        category = "Malware"
        tlp = "White"
        severity = "7.0"
    strings:
        $h1 = {50 61 73 73 77 6F 72 64 48 61 73 68} //PasswordHash
        $h2 = {50 61 73 73 77 6F 72 64 53 61 6C 74} //PasswordSalt
        $h3 = {5B 6F 78 46 65 79} //[oxFey

        // packed
        $u1 = "SPAWNWND=" wide
        $u2 = "DHLLPPTTXX" wide
        $u3 = "/PASSWORD=password" wide
        
    condition:
        uint16(0) == 0x5a4d and math.entropy(0, filesize) >= 7.75 and 
        filesize < 3350KB and all of ($h*) and 2 of ($u*)
}
