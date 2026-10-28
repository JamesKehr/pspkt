namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class TransportOutcomeScript
    {
        private readonly OutcomeKind[] _outcomes;
        private readonly int[] _increments;

        private TransportOutcomeScript(OutcomeKind[] outcomes, int[] increments)
        {
            _outcomes = outcomes;
            _increments = increments;
        }

        internal enum OutcomeKind
        {
            KnownShortWriteIncrement = 1,
            IndeterminateWrite = 2,
            FaultedWrite = 3,
            DelayCompletionDelivery = 4,
            ForeignGenerationReferenceDelivery = 5
        }

        internal int StepCount { get { return _outcomes.Length; } }

        internal static TransportOutcomeScript Create(OutcomeKind[] outcomes, int[] byteIncrements)
        {
            if (outcomes == null || byteIncrements == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (outcomes.Length != byteIncrements.Length || outcomes.Length > 16)
            {
                throw BrokerLifecycleFailure.Argument("argument:range");
            }
            int phase = 0;
            for (int index = 0; index < outcomes.Length; index++)
            {
                OutcomeKind kind = outcomes[index];
                int increment = byteIncrements[index];
                if (kind < OutcomeKind.KnownShortWriteIncrement || kind > OutcomeKind.ForeignGenerationReferenceDelivery ||
                    (kind == OutcomeKind.KnownShortWriteIncrement && (increment < 1 || increment > LifecyclePolicy.MaximumChunkBytes)) ||
                    (kind != OutcomeKind.KnownShortWriteIncrement && increment != 0))
                {
                    throw BrokerLifecycleFailure.Argument("argument:range");
                }
                if (phase == 2 || (phase == 1 && (kind == OutcomeKind.KnownShortWriteIncrement || kind == OutcomeKind.DelayCompletionDelivery)) ||
                    (phase == 0 && kind == OutcomeKind.ForeignGenerationReferenceDelivery))
                {
                    throw BrokerLifecycleFailure.Argument("argument:context");
                }
                if (kind == OutcomeKind.DelayCompletionDelivery)
                {
                    phase = 1;
                }
                else if (kind != OutcomeKind.KnownShortWriteIncrement)
                {
                    phase = 2;
                }
            }
            return new TransportOutcomeScript((OutcomeKind[])outcomes.Clone(), (int[])byteIncrements.Clone());
        }

        internal OutcomeKind[] CopyOutcomes()
        {
            return (OutcomeKind[])_outcomes.Clone();
        }

        internal int[] CopyByteIncrements()
        {
            return (int[])_increments.Clone();
        }
    }
}
