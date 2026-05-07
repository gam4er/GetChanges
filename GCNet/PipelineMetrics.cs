using System.Threading;

namespace GCNet
{
    internal sealed class PipelineMetrics
    {
        private long _notificationsReceived;
        private long _incomingQueued;
        private long _incomingProcessed;
        private long _outgoingQueued;
        private long _eventsWritten;
        private long _metadataErrors;
        private long _writerErrors;
        private long _processingErrors;
        private long _lastLoggedNotificationBucket = -1;

        public long NotificationsReceived => Volatile.Read(ref _notificationsReceived);
        public long IncomingQueued => Volatile.Read(ref _incomingQueued);
        public long IncomingProcessed => Volatile.Read(ref _incomingProcessed);
        public long OutgoingQueued => Volatile.Read(ref _outgoingQueued);
        public long EventsWritten => Volatile.Read(ref _eventsWritten);
        public long MetadataErrors => Volatile.Read(ref _metadataErrors);
        public long WriterErrors => Volatile.Read(ref _writerErrors);
        public long ProcessingErrors => Volatile.Read(ref _processingErrors);

        public long IncrementNotificationsReceived()
        {
            return Interlocked.Increment(ref _notificationsReceived);
        }

        public void IncrementIncomingQueued()
        {
            Interlocked.Increment(ref _incomingQueued);
        }

        public void IncrementIncomingProcessed()
        {
            Interlocked.Increment(ref _incomingProcessed);
        }

        public void IncrementOutgoingQueued()
        {
            Interlocked.Increment(ref _outgoingQueued);
        }

        public void IncrementEventsWritten()
        {
            Interlocked.Increment(ref _eventsWritten);
        }

        public void IncrementMetadataErrors()
        {
            Interlocked.Increment(ref _metadataErrors);
        }

        public void IncrementWriterErrors()
        {
            Interlocked.Increment(ref _writerErrors);
        }

        public void IncrementProcessingErrors()
        {
            Interlocked.Increment(ref _processingErrors);
        }

        public void MaybeLogSnapshot(int incomingDepth, int outgoingDepth)
        {
            var bucket = NotificationsReceived / 100;
            if (bucket == 0)
            {
                return;
            }

            var previousBucket = Interlocked.Read(ref _lastLoggedNotificationBucket);
            if (previousBucket == bucket)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _lastLoggedNotificationBucket, bucket, previousBucket) != previousBucket)
            {
                return;
            }

            LogSnapshot("periodic", incomingDepth, outgoingDepth);
        }

        public void LogSnapshot(string reason, int incomingDepth, int outgoingDepth)
        {
            AppConsole.Log(
                "pipeline-stats: reason=" + reason
                + " notifications=" + NotificationsReceived
                + " incomingQueued=" + IncomingQueued
                + " incomingProcessed=" + IncomingProcessed
                + " outgoingQueued=" + OutgoingQueued
                + " written=" + EventsWritten
                + " metadataErrors=" + MetadataErrors
                + " writerErrors=" + WriterErrors
                + " processingErrors=" + ProcessingErrors
                + " incomingDepth=" + incomingDepth
                + " outgoingDepth=" + outgoingDepth);
        }
    }
}
