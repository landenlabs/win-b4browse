// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;

namespace BrowseSafe
{
    /// <summary>How a background action failed - drives the colour/grouping in the viewer.</summary>
    public enum ErrorCategory
    {
        /// <summary>The agent ran past its time budget and was killed (e.g. a firewall silently
        /// dropping outbound packets so a probe never returns).</summary>
        Timeout,
        /// <summary>The agent returned output that could not be parsed (malformed/garbled JSON).</summary>
        ParseError,
        /// <summary>The agent threw, wrote to stderr, or exited non-zero with no usable output.</summary>
        Error,
    }

    /// <summary>One recorded failure of a background action.</summary>
    /// <param name="TimeLocal">When it was logged (local time).</param>
    /// <param name="Category">Failure kind.</param>
    /// <param name="Source">The check/method that triggered it (from CallerMemberName).</param>
    /// <param name="Message">One-line summary shown in the list.</param>
    /// <param name="Detail">Optional verbose text (stderr, exception, output snippet).</param>
    public sealed record ErrorEntry(
        DateTime TimeLocal, ErrorCategory Category, string Source, string Message, string? Detail);

    /// <summary>
    /// Process-wide, thread-safe sink for background-action failures so they aren't silently
    /// swallowed. The diagnostic runners (<c>RunPowerShellJson</c>, <c>RunPowerShellArray</c>,
    /// <c>RunCapture</c>) and the report driver feed it; the GUI surfaces the count in the status
    /// bar and the entries in <see cref="ErrorLogDialog"/>, and headless runs flush it to stderr.
    /// Bounded ring (oldest dropped past <see cref="MaxEntries"/>) so a misbehaving check can't
    /// grow memory without bound. Every method is no-throw - logging must never perturb the
    /// failure path it is recording.
    /// </summary>
    public static class ErrorLog
    {
        private const int MaxEntries = 500;
        private static readonly ConcurrentQueue<ErrorEntry> _entries = new();
        private static int _count;

        /// <summary>Raised after the log changes (add or clear). May fire on a background thread,
        /// so UI subscribers must marshal to the UI thread.</summary>
        public static event Action? Changed;

        /// <summary>Number of entries currently held.</summary>
        public static int Count => Volatile.Read(ref _count);

        /// <summary>Records a failure. <paramref name="source"/> defaults to the calling method.</summary>
        public static void Add(
            ErrorCategory category, string message, string? detail = null,
            [System.Runtime.CompilerServices.CallerMemberName] string source = "")
        {
            try
            {
                _entries.Enqueue(new ErrorEntry(
                    DateTime.Now, category,
                    string.IsNullOrWhiteSpace(source) ? "(unknown)" : source,
                    message ?? "", detail));
                Interlocked.Increment(ref _count);

                // Trim the oldest entries past the cap.
                while (Volatile.Read(ref _count) > MaxEntries && _entries.TryDequeue(out _))
                    Interlocked.Decrement(ref _count);

                Changed?.Invoke();
            }
            catch { /* logging must never throw into a check */ }
        }

        /// <summary>A point-in-time copy of the entries, oldest first.</summary>
        public static IReadOnlyList<ErrorEntry> Snapshot() => _entries.ToArray();

        /// <summary>Empties the log and notifies subscribers.</summary>
        public static void Clear()
        {
            while (_entries.TryDequeue(out _)) { }
            Volatile.Write(ref _count, 0);
            try { Changed?.Invoke(); } catch { }
        }
    }
}
