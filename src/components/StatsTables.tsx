import type { IpStat, UsernameStat } from "@/lib/types";

const TH = "px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase";
const TH_NUM = `${TH} text-right`;
const TD = "px-3 py-1.5 text-[13px] text-muted";
const TD_NUM = `${TD} text-right font-mono tabular-nums`;

export default function StatsTables({
  topIps,
  topUsernames,
}: {
  topIps: IpStat[];
  topUsernames: UsernameStat[];
}) {
  return (
    <section aria-label="Statistics">
      <h2 className="text-sm font-medium tracking-wide text-faint uppercase">
        Statistics
      </h2>
      <div className="mt-4 grid gap-10 lg:grid-cols-2">
        <div>
          <h3 className="text-[13px] font-medium text-muted">
            Most active source addresses
          </h3>
          {topIps.length === 0 ? (
            <p className="mt-3 text-sm text-faint">No source addresses observed.</p>
          ) : (
            <div className="mt-2 overflow-x-auto"><table className="w-full min-w-[420px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th scope="col" className={TH}>Address</th>
                  <th scope="col" className={TH_NUM}>Attempts</th>
                  <th scope="col" className={TH_NUM}>Failed</th>
                  <th scope="col" className={TH_NUM}>OK</th>
                  <th scope="col" className={TH_NUM}>Users</th>
                </tr>
              </thead>
              <tbody>
                {topIps.map((s) => (
                  <tr key={s.ip} className="border-b border-line/60">
                    <td className={`${TD} font-mono break-all text-ink`}>
                      {s.ip}
                      {s.ipVersion === 6 && (
                        <span className="ml-2 text-[11px] text-faint">v6</span>
                      )}
                    </td>
                    <td className={TD_NUM}>{s.attempts}</td>
                    <td className={TD_NUM}>{s.failed}</td>
                    <td className={TD_NUM}>{s.successful}</td>
                    <td className={TD_NUM}>{s.distinctUsernames}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </div>

        <div>
          <h3 className="text-[13px] font-medium text-muted">
            Most targeted usernames
          </h3>
          {topUsernames.length === 0 ? (
            <p className="mt-3 text-sm text-faint">No usernames observed.</p>
          ) : (
            <div className="mt-2 overflow-x-auto"><table className="w-full min-w-[420px] border-collapse">
              <thead>
                <tr className="border-b border-line">
                  <th scope="col" className={TH}>Username</th>
                  <th scope="col" className={TH_NUM}>Attempts</th>
                  <th scope="col" className={TH_NUM}>Failed</th>
                  <th scope="col" className={TH_NUM}>OK</th>
                  <th scope="col" className={TH_NUM}>IPs</th>
                </tr>
              </thead>
              <tbody>
                {topUsernames.map((s) => (
                  <tr key={s.username} className="border-b border-line/60">
                    <td className={`${TD} font-mono break-all text-ink`}>
                      {s.username}
                      {s.privileged && (
                        <span className="ml-2 text-[11px] text-medium">privileged</span>
                      )}
                    </td>
                    <td className={TD_NUM}>{s.attempts}</td>
                    <td className={TD_NUM}>{s.failed}</td>
                    <td className={TD_NUM}>{s.successful}</td>
                    <td className={TD_NUM}>{s.distinctIps}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </div>
      </div>
    </section>
  );
}
