"""
Bias Detection Service

Monitors and detects demographic bias in matching results and job descriptions.
Implements:
- Language bias detection (gendered, age-related terms)
- Statistical bias analysis (disparate impact using 80% rule)
- Bias mitigation through reranking
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BiasReport:
    """Report of detected bias in text or matching results."""
    has_bias: bool = False
    bias_score: float = 0.0
    gender_bias: List[str] = field(default_factory=list)
    age_bias: List[str] = field(default_factory=list)
    other_bias: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    statistical_bias: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StatisticalBiasResult:
    """Result of statistical bias analysis."""
    bias_detected: bool = False
    disparity_ratio: float = 1.0
    affected_groups: List[str] = field(default_factory=list)
    group_stats: Dict[str, Dict[str, float]] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class BiasDetectionService:
    """
    Service for detecting and mitigating bias in matching.

    Analyzes:
    - Job descriptions for biased language
    - Matching results for statistical disparities
    - Recommendations for potential bias

    Usage:
        service = BiasDetectionService()

        # Check job description for biased language
        report = service.check_text_bias(job_description)
        if report.has_bias:
            print(f"Biased terms: {report.gender_bias}")

        # Check matching results for statistical bias
        bias = service.check_bias(matching_results, ['gender', 'age_group'])
        if bias['bias_detected']:
            print(f"Bias detected in: {bias['affected_groups']}")
    """

    # Gender-biased terms and neutral alternatives
    GENDER_BIASED_TERMS = {
        # Masculine-coded terms
        'aggressive': 'assertive',
        'ambitious': 'motivated',
        'dominant': 'leading',
        'competitive': 'results-driven',
        'ninja': 'expert',
        'rockstar': 'high performer',
        'guru': 'specialist',
        'hacker': 'developer',
        'manpower': 'workforce',
        'man-hours': 'person-hours',
        'chairman': 'chairperson',
        'foreman': 'supervisor',
        'mankind': 'humankind',
        'manmade': 'artificial',
        'salesman': 'salesperson',
        'fireman': 'firefighter',
        'policeman': 'police officer',
        'stewardess': 'flight attendant',
        'waitress': 'server',

        # Feminine-coded terms (that may limit applicants)
        'nurturing': 'supportive',
        'collaborative': 'team-oriented',  # only if overused
    }

    # Age-biased terms
    AGE_BIASED_TERMS = [
        'young',
        'youthful',
        'digital native',
        'recent graduate',
        'fresh graduate',
        'energetic',
        'dynamic',
        'mature',
        'seasoned',
        'overqualified',
        'cultural fit',  # Can mask age discrimination
    ]

    # Terms that may indicate discrimination
    PROBLEMATIC_TERMS = [
        ('native english speaker', 'fluent in English'),
        ('culture fit', 'values alignment'),
        ('must be local', 'based in [location]'),
        ('no visa sponsorship', 'visa sponsorship not available'),
        ('clean-shaven', None),  # Remove entirely
        ('unmarried', None),
        ('young and energetic', 'motivated'),
    ]

    # Minimum disparity ratio (80% rule from EEOC)
    DISPARITY_THRESHOLD = 0.8

    def __init__(self):
        pass

    def check_bias(
        self,
        matching_results: List[Dict],
        protected_attributes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Check for statistical bias in matching results.

        Uses the 80% rule (four-fifths rule) from EEOC guidelines.
        If selection rate for a protected group is less than 80%
        of the rate for the highest group, bias may be present.

        Args:
            matching_results: List of match results with demographic data
            protected_attributes: Attributes to check (e.g., 'gender', 'age_group')

        Returns:
            Dict with bias analysis results
        """
        result = {
            'bias_detected': False,
            'bias_score': 0.0,
            'affected_groups': [],
            'recommendations': [],
            'statistical_analysis': {},
            'sample_size': len(matching_results)
        }

        if not matching_results or len(matching_results) < 10:
            result['recommendations'].append(
                'Insufficient sample size for statistical bias analysis'
            )
            return result

        protected_attributes = protected_attributes or ['gender', 'age_group']

        # Analyze each protected attribute
        for attr in protected_attributes:
            analysis = self._analyze_attribute(matching_results, attr)
            result['statistical_analysis'][attr] = analysis

            if analysis['bias_detected']:
                result['bias_detected'] = True
                result['affected_groups'].append(attr)
                result['recommendations'].extend(analysis['recommendations'])

        # Calculate overall bias score
        if result['statistical_analysis']:
            ratios = [
                a.get('disparity_ratio', 1.0)
                for a in result['statistical_analysis'].values()
            ]
            # Bias score: how far below threshold
            min_ratio = min(ratios)
            if min_ratio < self.DISPARITY_THRESHOLD:
                result['bias_score'] = 1.0 - (min_ratio / self.DISPARITY_THRESHOLD)
            else:
                result['bias_score'] = 0.0

        return result

    def _analyze_attribute(
        self,
        results: List[Dict],
        attribute: str
    ) -> Dict[str, Any]:
        """Analyze bias for a specific protected attribute."""
        analysis = {
            'bias_detected': False,
            'disparity_ratio': 1.0,
            'group_scores': {},
            'group_counts': {},
            'selection_rates': {},
            'recommendations': []
        }

        # Group results by attribute value
        groups: Dict[str, List[float]] = {}
        for r in results:
            attr_value = str(r.get(attribute, 'unknown')).lower()
            if attr_value == 'unknown' or attr_value == 'none':
                continue

            if attr_value not in groups:
                groups[attr_value] = []
            groups[attr_value].append(float(r.get('overall_score', 0)))

        if len(groups) < 2:
            return analysis

        # Calculate statistics per group
        for group, scores in groups.items():
            if scores:
                analysis['group_counts'][group] = len(scores)
                analysis['group_scores'][group] = {
                    'mean': sum(scores) / len(scores),
                    'min': min(scores),
                    'max': max(scores),
                }

                # Selection rate: proportion above threshold (0.5)
                selected = sum(1 for s in scores if s >= 0.5)
                analysis['selection_rates'][group] = selected / len(scores)

        # Check for disparity using 80% rule
        if analysis['selection_rates']:
            max_rate = max(analysis['selection_rates'].values())

            if max_rate > 0:
                for group, rate in analysis['selection_rates'].items():
                    ratio = rate / max_rate
                    if ratio < analysis['disparity_ratio']:
                        analysis['disparity_ratio'] = ratio

                if analysis['disparity_ratio'] < self.DISPARITY_THRESHOLD:
                    analysis['bias_detected'] = True

                    # Find disadvantaged groups
                    disadvantaged = [
                        g for g, r in analysis['selection_rates'].items()
                        if max_rate > 0 and r / max_rate < self.DISPARITY_THRESHOLD
                    ]

                    analysis['recommendations'].append(
                        f"Potential {attribute} bias detected. "
                        f"Disparity ratio: {analysis['disparity_ratio']:.2f}. "
                        f"Affected groups: {', '.join(disadvantaged)}. "
                        f"Review scoring criteria for potential discrimination."
                    )

        return analysis

    def check_text_bias(self, text: str) -> BiasReport:
        """
        Check text (job description, requirements) for biased language.

        Args:
            text: Text to analyze

        Returns:
            BiasReport with findings and suggestions
        """
        report = BiasReport()

        if not text:
            return report

        text_lower = text.lower()

        # Check for gender-biased terms
        for biased_term, neutral in self.GENDER_BIASED_TERMS.items():
            if re.search(rf'\b{re.escape(biased_term)}\b', text_lower):
                report.gender_bias.append(biased_term)
                if neutral:
                    report.suggestions.append(
                        f"Replace '{biased_term}' with '{neutral}'"
                    )
                else:
                    report.suggestions.append(
                        f"Consider removing '{biased_term}'"
                    )

        # Check for age-biased terms
        for term in self.AGE_BIASED_TERMS:
            if re.search(rf'\b{re.escape(term)}\b', text_lower):
                report.age_bias.append(term)

        # Check for other problematic terms
        for problematic, replacement in self.PROBLEMATIC_TERMS:
            if problematic in text_lower:
                report.other_bias.append(problematic)
                if replacement:
                    report.suggestions.append(
                        f"Replace '{problematic}' with '{replacement}'"
                    )
                else:
                    report.suggestions.append(
                        f"Remove '{problematic}' - may be discriminatory"
                    )

        # Calculate bias score
        total_issues = (
            len(report.gender_bias) +
            len(report.age_bias) +
            len(report.other_bias)
        )

        if total_issues > 0:
            report.has_bias = True
            # Score increases with more issues, capped at 1.0
            report.bias_score = min(total_issues * 0.15, 1.0)

        # Add general suggestions
        if report.age_bias:
            report.suggestions.append(
                "Remove age-related terms to ensure fair consideration "
                "of candidates of all ages (ADEA compliance)"
            )

        if report.gender_bias and len(report.gender_bias) > 2:
            report.suggestions.append(
                "Consider using a gender decoder tool to identify "
                "additional masculine or feminine-coded language"
            )

        return report

    def mitigate_bias(
        self,
        matching_results: List[Dict],
        protected_attributes: Optional[List[str]] = None
    ) -> List[Dict]:
        """
        Apply bias mitigation to matching results.

        Uses group normalization to reduce disparities while
        maintaining overall ranking quality.

        Args:
            matching_results: Original match results
            protected_attributes: Attributes to consider for mitigation

        Returns:
            Reranked results with reduced bias
        """
        if not matching_results or len(matching_results) < 10:
            return matching_results

        protected_attributes = protected_attributes or ['gender', 'age_group']

        # Check if mitigation is needed
        bias_check = self.check_bias(matching_results, protected_attributes)
        if not bias_check['bias_detected']:
            return sorted(
                matching_results,
                key=lambda x: x.get('overall_score', 0),
                reverse=True
            )

        # Apply group normalization
        mitigated = self._apply_group_normalization(
            matching_results,
            protected_attributes
        )

        return sorted(
            mitigated,
            key=lambda x: x.get('adjusted_score', x.get('overall_score', 0)),
            reverse=True
        )

    def _apply_group_normalization(
        self,
        results: List[Dict],
        attributes: List[str]
    ) -> List[Dict]:
        """
        Apply group normalization to reduce disparities.

        Adjusts scores within each group to have similar distributions.
        """
        import copy
        import statistics

        mitigated = [copy.deepcopy(r) for r in results]

        for attr in attributes:
            # Group by attribute
            groups: Dict[str, List[int]] = {}
            for i, r in enumerate(mitigated):
                attr_value = str(r.get(attr, 'unknown'))
                if attr_value not in groups:
                    groups[attr_value] = []
                groups[attr_value].append(i)

            if len(groups) < 2:
                continue

            # Calculate global mean and std
            all_scores = [r.get('overall_score', 0) for r in mitigated]
            if not all_scores:
                continue

            global_mean = statistics.mean(all_scores)
            try:
                global_std = statistics.stdev(all_scores)
            except statistics.StatisticsError:
                global_std = 0.1

            # Normalize each group to global distribution
            for group, indices in groups.items():
                if len(indices) < 3:
                    continue

                group_scores = [mitigated[i].get('overall_score', 0) for i in indices]
                group_mean = statistics.mean(group_scores)

                try:
                    group_std = statistics.stdev(group_scores)
                except statistics.StatisticsError:
                    group_std = 0.1

                if group_std == 0:
                    group_std = 0.1

                # Z-score normalize and rescale
                for i in indices:
                    original = mitigated[i].get('overall_score', 0)
                    z_score = (original - group_mean) / group_std
                    adjusted = global_mean + (z_score * global_std)

                    # Blend original and adjusted (80% adjusted, 20% original)
                    # to maintain some ranking validity
                    blended = (adjusted * 0.8) + (original * 0.2)

                    # Clip to valid range
                    mitigated[i]['adjusted_score'] = max(0.0, min(1.0, blended))

        return mitigated

    def check_for_bias(self, results: List) -> BiasReport:
        """
        Check a list of MatchResult model instances for bias patterns.

        Args:
            results: List of MatchResult model instances

        Returns:
            BiasReport with findings
        """
        report = BiasReport()

        if not results or len(results) < 10:
            return report

        # Convert to dicts for analysis
        result_dicts = []
        for r in results:
            try:
                result_dicts.append({
                    'overall_score': float(r.overall_score),
                    'gender': getattr(r, 'candidate_gender', None),
                    'age_group': getattr(r, 'candidate_age_group', None),
                })
            except (AttributeError, ValueError):
                continue

        if len(result_dicts) < 10:
            return report

        # Analyze score distribution
        scores = [r['overall_score'] for r in result_dicts]

        import statistics
        try:
            mean = statistics.mean(scores)
            stdev = statistics.stdev(scores)

            # High variance may indicate inconsistent scoring
            if stdev > 0.25:
                report.other_bias.append(
                    f"High score variance ({stdev:.2f}) may indicate "
                    f"inconsistent scoring criteria"
                )
                report.suggestions.append(
                    "Review scoring algorithm for potential bias sources"
                )

            # Check for bimodal distribution (potential discrimination)
            below_mean = sum(1 for s in scores if s < mean - stdev)
            above_mean = sum(1 for s in scores if s > mean + stdev)

            if below_mean > len(scores) * 0.3 and above_mean > len(scores) * 0.3:
                report.other_bias.append(
                    "Bimodal score distribution detected - "
                    "may indicate systematic bias"
                )

        except statistics.StatisticsError:
            pass

        # Run statistical bias check
        bias_result = self.check_bias(result_dicts)
        if bias_result['bias_detected']:
            report.has_bias = True
            report.statistical_bias = bias_result
            report.suggestions.extend(bias_result['recommendations'])

        report.has_bias = bool(report.other_bias or report.statistical_bias)
        report.bias_score = bias_result.get('bias_score', 0.0)

        return report

    def get_bias_summary(self, report: BiasReport) -> str:
        """Generate a human-readable summary of bias findings."""
        if not report.has_bias:
            return "No significant bias detected."

        parts = []

        if report.gender_bias:
            parts.append(
                f"Gender-biased terms found: {', '.join(report.gender_bias[:5])}"
            )

        if report.age_bias:
            parts.append(
                f"Age-biased terms found: {', '.join(report.age_bias[:5])}"
            )

        if report.other_bias:
            parts.append(
                f"Other concerns: {', '.join(report.other_bias[:3])}"
            )

        if report.statistical_bias:
            parts.append(
                f"Statistical bias score: {report.bias_score:.2f}"
            )

        summary = " | ".join(parts)
        return f"Bias detected (score: {report.bias_score:.2f}): {summary}"
