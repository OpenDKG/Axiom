// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text;
using Axiom.Contracts.Ipc;
using Axiom.Contracts.Monitoring;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class IpcConnectionHandlerTests
{
    [Fact]
    public async Task Oversized_request_with_a_blocked_writer_is_bounded_by_its_own_deadline()
    {
        var stream = new BlockedWriteStream(new string('x', IpcProtocol.MaxMessageBytes + 16));

        var handler = IpcConnectionHandler.ServeAsync(
            stream,
            "uid:0",
            Processor(),
            log: null,
            responseWriteTimeout: TimeSpan.FromMilliseconds(150),
            cancellationToken: CancellationToken.None);

        var completed = await Task.WhenAny(handler, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(handler, completed);
        await handler; // A cancelled write is swallowed; the handler must not rethrow.
        Assert.True(stream.WriteAttempted);
    }

    [Fact]
    public async Task A_cancelled_connection_releases_the_handler()
    {
        var stream = new StalledReadStream();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var handler = IpcConnectionHandler.ServeAsync(
            stream,
            "uid:0",
            Processor(),
            log: null,
            cancellationToken: cancellation.Token);

        var completed = await Task.WhenAny(handler, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(handler, completed);
        await handler;
    }

    private static IpcRequestProcessor Processor() => new(
        snapshot: () => new ConnectionSnapshot
        {
            CapturedUtc = DateTimeOffset.UtcNow,
            Connections = [],
            ProcessCount = 0,
            SourceName = "test",
        },
        health: () => new ServiceHealth
        {
            Status = "running",
            SourceName = "test",
            UptimeSeconds = 1,
            ProcessCount = 0,
            ConnectionCount = 0,
            PollIntervalSeconds = 1,
        });

    private sealed class BlockedWriteStream(string oversizedLine) : Stream
    {
        private readonly byte[] _input = Encoding.UTF8.GetBytes(oversizedLine);

        private int _read;

        public bool WriteAttempted { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_read >= _input.Length)
            {
                return Task.FromResult(0);
            }

            var take = Math.Min(count, _input.Length - _read);
            Array.Copy(_input, _read, buffer, offset, take);
            _read += take;
            return Task.FromResult(take);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_read >= _input.Length)
            {
                return ValueTask.FromResult(0);
            }

            var take = Math.Min(buffer.Length, _input.Length - _read);
            _input.AsSpan(_read, take).CopyTo(buffer.Span);
            _read += take;
            return ValueTask.FromResult(take);
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            WriteAttempted = true;
            return Task.Delay(Timeout.Infinite, cancellationToken);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            WriteAttempted = true;
            return new ValueTask(Task.Delay(Timeout.Infinite, cancellationToken));
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class StalledReadStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.Infinite, cancellationToken).ContinueWith(_ => 0, TaskScheduler.Default);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            new(Task.Delay(Timeout.Infinite, cancellationToken).ContinueWith(_ => 0, TaskScheduler.Default));

        public override void Write(byte[] buffer, int offset, int count)
        {
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
