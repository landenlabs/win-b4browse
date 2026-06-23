// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;

namespace B4Browse
{
    public sealed class EnvVariableInfo
    {
        public string Name = "";
        public string RawValue = "";
        // When a variable contains multiple ';' delimited parts we create one EnvVariableInfo
        // per part and store that single part in Value. ParsedPaths kept for compatibility.
        public List<string> ParsedPaths = new List<string>();
        public string Value = ""; // single part (one PATH entry or the whole value when not split)
        public bool IsMachineScope = false;

        public bool HasInvalidPaths = false;
        public bool HasUserWritablePaths = false;
        public bool IsCoreVariableAltered = false;
        public bool IsLengthRisk = false;

        public string DiagnosticRecommendation = "";

        // Optional inferred authors for the parsed paths (parallel to ParsedPaths when present)
        public List<string> InferredAuthors = new List<string>();

        /// <summary>True when this Machine-scope row is overridden by a User-scope entry with the
        /// same name. The variable's effective value comes from the User row instead.</summary>
        public bool IsShadowed = false;
    }
}
