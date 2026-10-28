using System.Threading;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class DispatchLease
    {
        private readonly CheckpointServiceLifecycle _owner;
        private readonly RunGenerationId _generation;
        private int _released;

        internal DispatchLease(CheckpointServiceLifecycle owner, RunGenerationId generation)
        {
            _owner = owner;
            _generation = generation;
        }

        internal RunGenerationId Generation { get { return _generation; } }

        internal void Release()
        {
            if (Interlocked.CompareExchange(ref _released, 1, 0) != 0)
            {
                return;
            }
            _owner.ReleaseDispatchLease(this);
        }
    }
}
