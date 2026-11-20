// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace B4Browse
{
    /// <summary>
    /// Hover text for colour-highlighted grid cells, taken from the panel's own Help text so the
    /// tooltip and the Help dialog never disagree. The Help body is parsed into its bullet / text
    /// lines; a highlighted cell is matched to the line that explains it, by the cell's text
    /// ("Review", "Intercept") and tie-broken by the cell's highlight colour ("Review (red)" vs
    /// "Review (yellow)"). Cells whose meaning is only a colour (e.g. a recency-tinted date) match
    /// the line that names that colour ("... (highlighted red)"). When nothing matches, a short
    /// "see Help" pointer is returned instead.
    /// </summary>
    public sealed class StatusTips
    {
        private const int WrapAt = 90;

        private sealed class Entry
        {
            public string Text = "";                       // full line, without the "- " bullet
            public string[] Names = Array.Empty<string>(); // label aliases ("Review", "Public CA", ...)
            public string[] LabelColours = Array.Empty<string>(); // colour words inside the label
            public bool NameIsColour;                      // label itself is a colour ("Yellow", "Red (Alert)")
            public bool StatusSection;                     // under a "# Status ..." / "# ... colours" heading
        }

        private static readonly string[] Colours = { "red", "yellow", "orange", "green", "blue" };
        private static readonly Regex LabelSplit = new(@"^(.{1,50}?)\s+-\s+(.+)$", RegexOptions.Compiled);
        private static readonly Regex Paren = new(@"\(([^)]*)\)", RegexOptions.Compiled);

        private readonly List<Entry> _entries = new();
        private readonly Dictionary<(string, string), string> _cache = new();

        public StatusTips(string helpBody)
        {
            bool statusSection = false;
            Entry? last = null;
            foreach (var raw in (helpBody ?? "").Split('\n'))
            {
                string line = raw.TrimEnd();
                if (line.StartsWith("#"))
                {
                    string h = line.TrimStart('#').Trim().ToLowerInvariant();
                    statusSection = h.Contains("status") || h.Contains("colour") || h.Contains("audit");
                    last = null;
                    continue;
                }
                if (line.Trim().Length == 0 || line.TrimStart().StartsWith(">")) { last = null; continue; }

                // Indented continuation of the previous bullet.
                if (last != null && line.StartsWith("  ") && !line.TrimStart().StartsWith("- "))
                {
                    last.Text += " " + line.Trim();
                    continue;
                }

                bool bullet = line.TrimStart().StartsWith("- ");
                string text = bullet ? line.TrimStart().Substring(2).Trim() : line.Trim();
                var e = new Entry { Text = Regex.Replace(text, @"\s{2,}", " "), StatusSection = statusSection };
                if (bullet) ParseLabel(e, text);
                _entries.Add(e);
                last = e;
            }
        }

        private static void ParseLabel(Entry e, string text)
        {
            var m = LabelSplit.Match(text);
            if (!m.Success) return;
            string label = m.Groups[1].Value.Trim();

            var names = new List<string>();
            foreach (Match p in Paren.Matches(label)) names.Add(p.Groups[1].Value.Trim());
            string bare = Paren.Replace(label, "").Trim();
            foreach (var part in bare.Split(new[] { " / " }, StringSplitOptions.RemoveEmptyEntries))
                names.Add(part.Trim());

            e.Names = names.Where(n => n.Length > 0).ToArray();
            string lower = label.ToLowerInvariant();
            e.LabelColours = Colours.Where(c => Regex.IsMatch(lower, $@"\b{c}\b")).ToArray();
            e.NameIsColour = Colours.Contains(bare.ToLowerInvariant());
        }

        /// <summary>Hover text for a highlighted cell, or "" when the highlight is neutral (grey / white).</summary>
        public string For(string cellText, Color back)
        {
            string colour = ColourOf(back);
            if (colour.Length == 0) return "";
            string text = (cellText ?? "").Trim();
            var key = (text, colour);
            if (_cache.TryGetValue(key, out var hit)) return hit;
            string tip = Wrap(Find(text, colour) ?? FallbackText(colour));
            _cache[key] = tip;
            return tip;
        }

        private static string FallbackText(string colour) =>
            $"Highlighted {colour} - see Help for what this means";

        private string? Find(string text, string colour)
        {
            bool Mentions(Entry e) => Regex.IsMatch(e.Text.ToLowerInvariant(), $@"\b{colour}\b")
                                   || (colour == "orange" && Regex.IsMatch(e.Text.ToLowerInvariant(), @"\byellow\b"));
            IEnumerable<Entry> Ranked(IEnumerable<Entry> es) => es.OrderByDescending(e => e.StatusSection);

            // 1. The cell text is a status label ("Review", "Intercept"); colour breaks ties.
            if (text.Length > 0)
            {
                var named = Ranked(_entries.Where(e => e.Names.Any(n => n.Equals(text, StringComparison.OrdinalIgnoreCase)))).ToList();
                if (named.Count > 0)
                    return (named.FirstOrDefault(e => e.LabelColours.Contains(colour))
                            ?? named.FirstOrDefault(e => e.LabelColours.Length == 0)
                            ?? named[0]).Text;
            }

            // 2. The cell text is named inside a line that also mentions this colour
            //    ("... highlighted yellow as Caution").
            if (text.Length >= 3 && text.Any(char.IsLetter))
            {
                var word = new Regex($@"\b{Regex.Escape(text)}\b", RegexOptions.IgnoreCase);
                var inLine = Ranked(_entries.Where(e => Mentions(e) && word.IsMatch(e.Text))).FirstOrDefault();
                if (inLine != null) return inLine.Text;
            }

            // 3. The colour itself is the meaning (recency tint, trend colour, "flagged red").
            var byColour = Ranked(_entries.Where(e =>
                (e.NameIsColour && e.LabelColours.Contains(colour)) ||
                Regex.IsMatch(e.Text.ToLowerInvariant(), $@"\b(highlighted|flagged|tinted)\s+{colour}\b") ||
                (e.Names.Length == 0 && e.StatusSection && Mentions(e)))).FirstOrDefault();
            return byColour?.Text;
        }

        /// <summary>Classifies a highlight background into a colour word ("" for neutral greys).</summary>
        private static string ColourOf(Color c)
        {
            if (c.IsEmpty || c.A == 0 || c.GetSaturation() < 0.15f) return "";
            float h = c.GetHue();
            if (h < 18 || h >= 330) return "red";
            if (h < 38) return "orange";
            if (h < 75) return "yellow";
            if (h < 170) return "green";
            if (h < 260) return "blue";
            return "red";
        }

        private static string Wrap(string s)
        {
            if (s.Length <= WrapAt) return s;
            var sb = new StringBuilder();
            int col = 0;
            foreach (var w in s.Split(' '))
            {
                if (col > 0 && col + 1 + w.Length > WrapAt) { sb.Append('\n'); col = 0; }
                else if (col > 0) { sb.Append(' '); col++; }
                sb.Append(w);
                col += w.Length;
            }
            return sb.ToString();
        }
    }
}
