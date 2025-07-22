import React from 'react';
import { createRoot } from 'react-dom/client';

function App() {
  const [metrics, setMetrics] = React.useState(null);

  React.useEffect(() => {
    fetch('/api/metrics/latest')
      .then((r) => r.json())
      .then(setMetrics)
      .catch(console.error);
  }, []);

  return (
    <div style={{ fontFamily: 'sans-serif', padding: '2rem' }}>
      <h1>FerroLink Dashboard</h1>
      {metrics ? (
        <pre>{JSON.stringify(metrics, null, 2)}</pre>
      ) : (
        <p>Loading…</p>
      )}
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />); 