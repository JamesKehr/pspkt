namespace Pspkt.Certification.BrokerLifecycle
{
    internal enum ServicePhase
    {
        ControllerCreated = 0,
        ControllerStarting = 1,
        ControllerActiveUnverified = 2,
        ControllerStopRequested = 3,
        ControllerQuiescing = 4,
        ControllerStoppedUnverified = 5,
        ControllerFaultedUnverified = 6
    }
}
