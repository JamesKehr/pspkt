namespace Pspkt.Certification.BrokerLifecycle
{
    internal enum LocalHelloProgress
    {
        LocalBootstrapNotStarted = 0,
        LocalWorkerHelloObservedUnverified = 1,
        LocalBootstrapObservedUnverified = 2
    }
}
