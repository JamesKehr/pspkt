namespace Pspkt.Certification.BrokerLifecycle
{
    internal interface IBoundedDuplexTransport
    {
        int AvailableBytes { get; }
        int WritableBytes { get; }
        bool EndOfStream { get; }
        bool Closed { get; }
        int Read(byte[] destination, int offset, int count);
        int Write(byte[] source, int offset, int count);
        void SignalEof();
    }
}
