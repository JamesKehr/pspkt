namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class RunGenerationId
    {
        private readonly object _ownerIdentity;
        private readonly ulong _value;

        internal RunGenerationId(ulong value, object ownerIdentity)
        {
            if (value == 0 || ownerIdentity == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:owner");
            }
            _ownerIdentity = ownerIdentity;
            _value = value;
        }

        internal object OwnerIdentity
        {
            get { return _ownerIdentity; }
        }

        internal ulong Value
        {
            get { return _value; }
        }
    }
}
