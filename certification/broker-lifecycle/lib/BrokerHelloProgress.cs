namespace Pspkt.Certification.BrokerLifecycle
{
    internal enum BrokerHelloProgress
    {
        BrokerBootstrapNotApplicableToRole = 0,
        BrokerBootstrapNotStarted = 1,
        BrokerHelloObservedUnverified = 2,
        BrokerHostHelloObservedUnverified = 3,
        BrokerContextObservedUnverified = 4,
        BrokerBootstrapObservedUnverified = 5
    }
}
