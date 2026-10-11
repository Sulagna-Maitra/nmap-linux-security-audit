
description = [[
Checks the SSH banner, identifies OpenSSH,
and displays a basic version-based recommendation.
]]

author = "Sulagna"
license = "Same as Nmap"
categories = {"safe", "discovery"}

local shortport = require "shortport"
local comm = require "comm"

portrule = shortport.port_or_service(22, "ssh")

action = function(host, port)
    local status, banner = comm.get_banner(host, port)

    if not status or not banner then
        return "Could not retrieve SSH banner."
    end

    local output = {}
    table.insert(output, "SSH Banner: " .. banner)

    if not banner:match("OpenSSH") then
        table.insert(output, "Status: Unknown SSH implementation.")
        return table.concat(output, "\n")
    end

    table.insert(output, "Status: OpenSSH server detected.")

    local version = banner:match("OpenSSH_([%d%.p]+)")

    if version then
        table.insert(output, "Detected Version: " .. version)

        if version:match("^8%.2") then
            table.insert(output,
                "Recommendation: Check installed security updates and consider upgrading if appropriate.")
        else
            table.insert(output,
                "Recommendation: Verify the installed version and security updates.")
        end
    else
        table.insert(output,
            "Recommendation: Verify the SSH version and security updates.")
    end

    return table.concat(output, "\n")
end
