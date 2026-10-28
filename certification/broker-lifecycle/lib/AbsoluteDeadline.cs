namespace Pspkt.Certification.BrokerLifecycle
{
    internal struct AbsoluteDeadline
    {
        private readonly ulong _ticks;

        internal AbsoluteDeadline(ulong ticks)
        {
            _ticks = ticks;
        }

        internal ulong Ticks
        {
            get { return _ticks; }
        }

        internal bool IsExpired(ulong now)
        {
            return now >= _ticks;
        }

        internal AbsoluteDeadline Earlier(AbsoluteDeadline other)
        {
            return _ticks <= other._ticks ? this : other;
        }
    }
}
