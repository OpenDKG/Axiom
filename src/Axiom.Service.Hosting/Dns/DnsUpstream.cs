// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;

namespace Axiom.Service.Hosting.Dns;

/// <summary>Parses a user-configured upstream resolver (<c>1.2.3.4</c>, <c>1.2.3.4:5353</c>, <c>[::1]:53</c>).</summary>
public static class DnsUpstream
{
    public static bool TryParse(string? value, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var text = value.Trim();
        var port = 53;
        var addressText = text;

        if (text.StartsWith('['))
        {
            var closing = text.IndexOf(']');
            if (closing < 0)
            {
                return false;
            }

            addressText = text[1..closing];
            if (closing + 1 < text.Length)
            {
                if (text[closing + 1] != ':' ||
                    !int.TryParse(text[(closing + 2)..], out port))
                {
                    return false;
                }
            }
        }
        else
        {
            var colon = text.LastIndexOf(':');
            if (colon > 0 && text.IndexOf(':') == colon)
            {
                addressText = text[..colon];
                if (!int.TryParse(text[(colon + 1)..], out port))
                {
                    return false;
                }
            }
        }

        if (port is < 1 or > 65535 ||
            !IPAddress.TryParse(addressText, out var address) ||
            IPAddress.IsLoopback(address))
        {
            return false;
        }

        endpoint = new IPEndPoint(address, port);
        return true;
    }
}
