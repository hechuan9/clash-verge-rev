import { Alert, Box, Button, Stack, TextField, Typography } from '@mui/material'
import { useEffect, useState } from 'react'

import { BasePage } from '@/components/base'
import type { HomeEgressView } from '@/services/bindings'
import { getHomeEgress, saveHomeEgress } from '@/services/cmds'
import { mutate } from '@/services/mutate'

function detail(error: unknown) {
  if (error && typeof error === 'object' && 'detail' in error)
    return String(error.detail)
  return String(error)
}

function domainsFromText(input: string) {
  const entries = input
    .split(/\s+/)
    .filter(Boolean)
    .map((entry) => {
      if (/^https?:\/\//i.test(entry))
        return new URL(entry).hostname.toLowerCase()
      return entry.toLowerCase()
    })
  return [...new Set(entries)]
}

export default function HomeEgressPage() {
  const [view, setView] = useState<HomeEgressView | null>(null)
  const [domains, setDomains] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const load = async () => {
    const next = await getHomeEgress()
    setView(next)
    setDomains(next.domains.join('\n'))
  }
  useEffect(() => {
    void load().catch((e) => setError(detail(e)))
  }, [])

  const apply = async () => {
    setBusy(true)
    setSaved(false)
    setError('')
    try {
      const wireguard = file ? await file.text() : null
      await mutate(() => saveHomeEgress(domainsFromText(domains), wireguard), {
        id: 'save-home-egress',
        errorNotice: false,
      })
      setFile(null)
      await load()
      setSaved(true)
    } catch (e) {
      setError(detail(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <BasePage title="VPN">
      <Stack
        spacing={2.5}
        sx={{ maxWidth: 640, p: 2 }}
        onChange={() => setSaved(false)}
      >
        <Typography>
          清单内的站点通过 WireGuard 出口访问。其他站点使用订阅原有规则。
        </Typography>
        {error && <Alert severity="error">{error}</Alert>}
        {saved && <Alert severity="success">分流配置已应用</Alert>}
        <Box>
          <Typography variant="body2" sx={{ mb: 1 }}>
            WireGuard · {file?.name ?? view?.server ?? '尚未导入'}
          </Typography>
          <Button component="label" variant="outlined" disabled={busy}>
            导入 WireGuard .conf
            <input
              hidden
              type="file"
              accept=".conf"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null)
                e.target.value = ''
                setSaved(false)
              }}
            />
          </Button>
        </Box>
        <TextField
          multiline
          minRows={7}
          label="使用 VPN 的站点"
          value={domains}
          disabled={busy}
          helperText="每行一个域名或 URL。*.claude.ai 包含主域名及所有子域名。"
          onChange={(e) => setDomains(e.target.value)}
        />
        <Box>
          <Button
            variant="contained"
            onClick={() => void apply()}
            disabled={busy || !view || (!view.server && !file)}
          >
            {busy ? '正在应用…' : '应用配置'}
          </Button>
        </Box>
      </Stack>
    </BasePage>
  )
}
