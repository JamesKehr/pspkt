using System.Collections.Generic;

namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class DeterministicScheduler
    {
        private readonly RunGenerationId _generation;
        private readonly Queue<ScheduledWork> _work = new Queue<ScheduledWork>();

        internal DeterministicScheduler(RunGenerationId generation)
        {
            _generation = generation;
        }

        internal int Count { get { return _work.Count; } }

        internal void Schedule(int kind)
        {
            if (_work.Count >= LifecyclePolicy.MaximumSchedulerItems)
            {
                throw BrokerLifecycleFailure.Reject("transport:capacity");
            }
            _work.Enqueue(new ScheduledWork(_generation, kind));
        }

        internal bool TryTake(RunGenerationId generation, out int kind)
        {
            if (!object.ReferenceEquals(generation, _generation))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:stale-generation");
            }
            if (_work.Count == 0)
            {
                kind = 0;
                return false;
            }
            ScheduledWork item = _work.Dequeue();
            if (!object.ReferenceEquals(item.Generation, generation))
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:stale-generation");
            }
            kind = item.Kind;
            return true;
        }

        private sealed class ScheduledWork
        {
            internal readonly RunGenerationId Generation;
            internal readonly int Kind;

            internal ScheduledWork(RunGenerationId generation, int kind)
            {
                Generation = generation;
                Kind = kind;
            }
        }
    }
}
