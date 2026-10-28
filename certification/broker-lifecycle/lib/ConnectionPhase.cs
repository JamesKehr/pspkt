namespace Pspkt.Certification.BrokerLifecycle
{
    internal enum ConnectionPhase
    {
        TransportNotApplicableToRole = 0,
        TransportNotOpened = 1,
        TransportOpenUnverified = 2,
        BootstrapObservedUnverified = 3,
        ApplicationObservedUnverified = 4,
        TransportDrainingUnverified = 5,
        LocalObservationSealedUnverified = 6,
        TransportClosedUnverified = 7
    }
}
