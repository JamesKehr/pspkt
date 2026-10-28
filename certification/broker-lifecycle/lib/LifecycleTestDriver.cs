namespace Pspkt.Certification.BrokerLifecycle
{
    internal sealed class LifecycleTestDriver
    {
        private CheckpointServiceLifecycle _primary;
        private CheckpointServiceLifecycle _foreign;
        private PendingTransportOperation _primaryOperation;
        private PendingTransportOperation _foreignOperation;
        private TransportOutcomeScript _primaryScript;
        private TransportOutcomeScript _foreignScript;
        private bool _disposed;

        private LifecycleTestDriver(CheckpointServiceLifecycle primary, CheckpointServiceLifecycle foreign)
        {
            _primary = primary;
            _foreign = foreign;
        }

        internal bool HasPrimaryHeldCompletion
        {
            get
            {
                RequireLive();
                _primary.EnterOwner();
                try { return _primaryOperation != null && _primaryOperation.HasHeldCompletion; }
                finally { _primary.ExitOwner(); }
            }
        }

        internal bool HasForeignHeldCompletion
        {
            get
            {
                RequireLive();
                if (_foreign == null)
                {
                    return false;
                }
                _foreign.EnterOwner();
                try { return _foreignOperation != null && _foreignOperation.HasHeldCompletion; }
                finally { _foreign.ExitOwner(); }
            }
        }

        internal string PrimaryWriteRetirementReason
        {
            get
            {
                RequireLive();
                _primary.EnterOwner();
                try { return _primaryOperation == null ? string.Empty : _primaryOperation.RetirementReason; }
                finally { _primary.ExitOwner(); }
            }
        }

        internal static LifecycleTestDriver Create(CheckpointServiceLifecycle primary, CheckpointServiceLifecycle foreign)
        {
            if (primary == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (object.ReferenceEquals(primary, foreign))
            {
                throw BrokerLifecycleFailure.Argument("argument:owner");
            }
            return new LifecycleTestDriver(primary, foreign);
        }

        internal void BindPrimaryWrite(string channel, TransportOutcomeScript script)
        {
            Bind(false, channel, script);
        }

        internal void BindForeignWrite(string channel, TransportOutcomeScript script)
        {
            Bind(true, channel, script);
        }

        internal void DeliverPrimaryCompletion(string channel)
        {
            Deliver(false, false, channel);
        }

        internal void DeliverForeignCompletion(string channel)
        {
            Deliver(true, false, channel);
        }

        internal void DeliverForeignCompletionToPrimary(string channel)
        {
            Deliver(true, true, channel);
        }

        internal TransportOutcomeScript.OutcomeKind[] CopyConsumedPrimaryOutcomes()
        {
            RequireLive();
            _primary.EnterOwner();
            try
            {
                return _primaryOperation == null ? new TransportOutcomeScript.OutcomeKind[0] : _primaryOperation.CopyConsumedOutcomes();
            }
            finally { _primary.ExitOwner(); }
        }

        internal TransportOutcomeScript.OutcomeKind[] CopyConsumedForeignOutcomes()
        {
            RequireLive();
            if (_foreign == null)
            {
                return new TransportOutcomeScript.OutcomeKind[0];
            }
            _foreign.EnterOwner();
            try
            {
                return _foreignOperation == null ? new TransportOutcomeScript.OutcomeKind[0] : _foreignOperation.CopyConsumedOutcomes();
            }
            finally { _foreign.ExitOwner(); }
        }

        internal void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            CheckpointServiceLifecycle primary = _primary;
            CheckpointServiceLifecycle foreign = _foreign;
            primary.EnterOwner();
            bool foreignEntered = false;
            try
            {
                if (foreign != null)
                {
                    foreign.EnterOwner();
                    foreignEntered = true;
                }
                if (!IsRetired(_primaryOperation) || !IsRetired(_foreignOperation))
                {
                    throw BrokerLifecycleFailure.Reject("lifecycle:dispose-before-quiescence");
                }
                _primaryOperation = null;
                _foreignOperation = null;
                _primaryScript = null;
                _foreignScript = null;
                _primary = null;
                _foreign = null;
                _disposed = true;
            }
            finally
            {
                if (foreignEntered)
                {
                    foreign.ExitOwner();
                }
                primary.ExitOwner();
            }
        }

        private void Bind(bool foreign, string channel, TransportOutcomeScript script)
        {
            RequireLive();
            if (channel == null || script == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (foreign && _foreign == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            if ((foreign ? _foreignOperation : _primaryOperation) != null)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            if (!foreign && HasForeignSuffix(script))
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            CheckpointServiceLifecycle controller = foreign ? _foreign : _primary;
            controller.EnterOwner();
            try
            {
                PendingTransportOperation operation = controller.GetPendingWrite(channel);
                if (_foreign != null)
                {
                    CheckpointServiceLifecycle other = foreign ? _primary : _foreign;
                    other.EnterOwner();
                    try
                    {
                        PendingTransportOperation peer = other.GetPendingWrite(channel);
                        ValidatePair(operation, peer);
                    }
                    finally { other.ExitOwner(); }
                }
                operation.BindOutcomeScript(script);
                if (foreign)
                {
                    _foreignOperation = operation;
                    _foreignScript = script;
                }
                else
                {
                    _primaryOperation = operation;
                    _primaryScript = script;
                }
            }
            finally { controller.ExitOwner(); }
        }

        private void Deliver(bool foreign, bool toPrimary, string channel)
        {
            RequireLive();
            if (channel == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:null");
            }
            if (foreign && _foreign == null)
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            PendingTransportOperation operation = foreign ? _foreignOperation : _primaryOperation;
            TransportOutcomeScript script = foreign ? _foreignScript : _primaryScript;
            if (operation == null)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:state");
            }
            if (operation.Channel != channel || toPrimary != HasForeignSuffix(script))
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            CheckpointServiceLifecycle origin = foreign ? _foreign : _primary;
            PendingTransportOperation.WriteCompletion completion;
            origin.EnterOwner();
            try { completion = operation.ClaimHeldCompletion(); }
            finally { origin.ExitOwner(); }
            (toPrimary ? _primary : origin).ApplyWriteCompletion(completion);
        }

        private static bool HasForeignSuffix(TransportOutcomeScript script)
        {
            if (script == null)
            {
                return false;
            }
            TransportOutcomeScript.OutcomeKind[] outcomes = script.CopyOutcomes();
            return outcomes.Length != 0 && outcomes[outcomes.Length - 1] == TransportOutcomeScript.OutcomeKind.ForeignGenerationReferenceDelivery;
        }

        private static bool IsRetired(PendingTransportOperation operation)
        {
            return operation == null || (operation.Retired && !operation.HasHeldCompletion && !operation.HasOutstandingDelivery);
        }

        private static void ValidatePair(PendingTransportOperation left, PendingTransportOperation right)
        {
            if (left.Generation.Value != 1 || right.Generation.Value != 1 ||
                left.OperationNumber != 1 || right.OperationNumber != 1 ||
                left.Channel != "LocalIpc" || right.Channel != "LocalIpc" ||
                left.Direction != "WorkerToBroker" || right.Direction != "WorkerToBroker" ||
                object.ReferenceEquals(left.Generation, right.Generation) ||
                object.ReferenceEquals(left.Generation.OwnerIdentity, right.Generation.OwnerIdentity) ||
                object.ReferenceEquals(left, right) || left.Episode.HasStarted || right.Episode.HasStarted)
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            byte[] first = left.CopyFrameBytes();
            byte[] second = right.CopyFrameBytes();
            if (first.Length != second.Length)
            {
                throw BrokerLifecycleFailure.Argument("argument:context");
            }
            for (int index = 0; index < first.Length; index++)
            {
                if (first[index] != second[index])
                {
                    throw BrokerLifecycleFailure.Argument("argument:context");
                }
            }
        }

        private void RequireLive()
        {
            if (_disposed)
            {
                throw BrokerLifecycleFailure.Reject("lifecycle:disposed");
            }
        }
    }
}
