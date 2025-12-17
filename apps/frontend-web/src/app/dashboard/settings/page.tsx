"use client"

import { useState } from "react"
import { Formik, Form, Field } from "formik"
import * as Yup from "yup"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"

const alertSettingsSchema = Yup.object().shape({
  emailNotifications: Yup.boolean(),
  slackWebhook: Yup.string().url("Invalid URL"),
  criticalThreshold: Yup.number().min(1).max(100),
  refreshInterval: Yup.number().min(10).max(300),
})

export default function SettingsPage() {
  const [saveSuccess, setSaveSuccess] = useState(false)

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground mt-2">Configure dashboard preferences and alerts</p>
      </div>

      <Formik
        initialValues={{
          emailNotifications: true,
          slackWebhook: "https://hooks.slack.com/services/...",
          criticalThreshold: 50,
          refreshInterval: 30,
        }}
        validationSchema={alertSettingsSchema}
        onSubmit={(values) => {
          console.log("Settings saved:", values)
          setSaveSuccess(true)
          setTimeout(() => setSaveSuccess(false), 2000)
        }}
      >
        {({ values, errors, touched }) => (
          <Form className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Alert Configuration</CardTitle>
                <CardDescription>Configure how you receive threat notifications</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="emailNotifications" className="flex items-center gap-2 cursor-pointer">
                    <Field as={Switch} id="emailNotifications" name="emailNotifications" />
                    <span>Email Notifications</span>
                  </Label>
                  <p className="text-sm text-muted-foreground ml-0">Receive email alerts for critical threats</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="slackWebhook">Slack Webhook URL</Label>
                  <Field
                    as={Input}
                    id="slackWebhook"
                    name="slackWebhook"
                    placeholder="https://hooks.slack.com/services/..."
                  />
                  {errors.slackWebhook && touched.slackWebhook && (
                    <p className="text-sm text-red-600">{errors.slackWebhook}</p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="criticalThreshold">Critical Alert Threshold (%)</Label>
                  <Field as={Input} id="criticalThreshold" name="criticalThreshold" type="number" min="1" max="100" />
                  <p className="text-sm text-muted-foreground">
                    Trigger critical alerts when confidence is above this percentage
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="refreshInterval">Refresh Interval (seconds)</Label>
                  <Field as={Input} id="refreshInterval" name="refreshInterval" type="number" min="10" max="300" />
                  <p className="text-sm text-muted-foreground">Dashboard auto-refresh interval</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Honeypot Selection</CardTitle>
                <CardDescription>Choose which honeypots to monitor</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <Field type="checkbox" name="honeypots" value="ssh" />
                  <span className="text-sm">SSH Honeypot (Cowrie)</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <Field type="checkbox" name="honeypots" value="web" />
                  <span className="text-sm">Web Honeypot (Dionaea)</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <Field type="checkbox" name="honeypots" value="iot" />
                  <span className="text-sm">IoT Honeypot (Conpot)</span>
                </label>
              </CardContent>
            </Card>

            <div className="flex items-center gap-2">
              <Button type="submit">Save Settings</Button>
              {saveSuccess && <Badge className="bg-green-600">Settings saved successfully</Badge>}
            </div>
          </Form>
        )}
      </Formik>
    </div>
  )
}
