
description = [[
Retrieves the SSH banner and identifies the OpenSSH version.
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

    if banner:match("OpenSSH") then
        table.insert(output, "SSH Implementation: OpenSSH")

        local version = banner:match("OpenSSH_([%d%.p]+)")
        if version then
            table.insert(output, "Detected Version: " .. version)
        end
    else
        table.insert(output, "SSH Implementation: Unknown")
    end

    return table.concat(output, "\n")
end
