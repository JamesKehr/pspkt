namespace Pspkt.Certification.BrokerLifecycle
{
    internal enum TransportOperationStatus
    {
        Pending = 0,
        Completed = 1,
        EndOfStream = 2,
        Aborted = 3,
        TimedOut = 4,
        Faulted = 5
    }
}
