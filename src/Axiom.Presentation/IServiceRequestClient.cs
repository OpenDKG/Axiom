// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// The only service surface the portable UI uses: typed local commands. Tests supply a fake so
/// service-offline states can be verified without opening a pipe.
/// </summary>
public interface IServiceRequestClient
{
    Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken);
}
