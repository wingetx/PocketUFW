"""Counter read/feedback contract. Loading, busy state, and reset safety are exercised by TideUiTest on Android."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] /
          'android/app/src/main/java/io/github/pocketufw/MainActivity.kt')


class LoadingUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SOURCE.read_text()

    def test_counter_refresh_shows_feedback_and_does_not_trigger_full_inspection(self):
        code = self.code
        start = code.index('fun refreshCounters() {')
        stop = code.index('    TideScreen(', start)
        path = code[start:stop]
        self.assertIn('client.refreshCounterActivity()', path)
        self.assertNotIn('client.inspectDashboard()', path)
        self.assertIn('counterRefreshing = true', path)
        self.assertIn('counterRefreshing = false', path)
        self.assertIn('finally {', path)
        self.assertIn('if (fresh.measured)', path)
        self.assertIn('Counters refreshed at', path)
        self.assertIn('counterRefreshNote = fresh.error', path)
        self.assertIn('DateFormat.MEDIUM', path)
        counters = (SOURCE.parent / 'TideCounters.kt').read_text()
        self.assertIn('loading = ui.counterRefreshing, loadingLabel = "Refreshing…"', counters)
        screen = (SOURCE.parent / 'TideScreen.kt').read_text()
        # Feedback is now fixed outside the scroll, so Reset cannot move under
        # a second tap. It is deliberately not inserted in TideCounters.
        self.assertIn('ui.counterRefreshNote.isNotEmpty()', screen)
        self.assertIn('snackbarHost = {', screen)
        self.assertNotIn('if (ui.counterRefreshNote.isNotEmpty())', counters)
        self.assertIn('Last checked:', counters)
        self.assertIn('DateFormat.getTimeInstance(DateFormat.MEDIUM)', code)



if __name__ == '__main__':
    unittest.main()
